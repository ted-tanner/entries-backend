use actix_web::{web, HttpResponse};
use log::error;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::definitions::*;
use crate::env;
use crate::handlers::error::ServerError;
use crate::handlers::request_io::{
    CredentialPair, RefreshToken, SigninToken, SigninTokenOtpPair, TokenPair,
};
use crate::middleware;
use crate::utils::db;
use crate::utils::{jwt, otp, password_hasher};

pub async fn sign_in(
    db_thread_pool: web::Data<DbThreadPool>,
    credentials: web::Json<CredentialPair>,
) -> Result<HttpResponse, ServerError> {
    const INVALID_CREDENTIALS_MSG: &str = "Incorrect email or password";

    if !credentials.validate_email_address().is_valid() {
        return Err(ServerError::InvalidFormat(Some("Invalid email address")));
    }

    let password = credentials.password.clone();

    let db_thread_pool_copy = db_thread_pool.clone();

    let user = match web::block(move || {
        let db_connection = db_thread_pool_copy
            .get()
            .expect("Failed to access database thread pool");

        db::user::get_user_by_email(&db_connection, &credentials.email)
    })
        .await?
    {
        Ok(u) => u,
        Err(_) => return Err(ServerError::UserUnauthorized(Some(INVALID_CREDENTIALS_MSG))),
    };

    let attempts = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        db::auth::get_and_increment_password_attempt_count(&db_connection, user.id)
    })
        .await?
    {
        Ok(a) => a,
        Err(e) => {
            error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(
                "Failed to check password attempt count",
            )));
        }
    };

    if attempts > env::CONF.security.password_max_attempts {
        return Err(ServerError::AccessForbidden(
            Some("Too many login attempts. Try again in a few minutes.")
        ));
    }

    let does_password_match_hash =
        web::block(move || password_hasher::verify_hash(&password, &user.password_hash)).await?;

    if does_password_match_hash {
        let signin_token = jwt::generate_signin_token(jwt::JwtParams {
            user_id: &user.id,
            user_email: &user.email,
            user_currency: &user.currency,
        });

        let signin_token = match signin_token {
            Ok(signin_token) => signin_token,
            Err(e) => {
                error!("{}", e);
                return Err(ServerError::InternalError(Some(
                    "Failed to generate sign-in token for user",
                )));
            }
        };

        let signin_token = SigninToken {
            signin_token: signin_token.to_string(),
        };

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_secs();

        // Add the lifetime of a generated code to the system time so the code doesn't expire quickly after
        // it is sent. The verification endpoint will check the code for the current time as well as a future
        // code. The real lifetime of the code the user gets is somewhere between OTP_LIFETIME_SECS and
        // OTP_LIFETIME_SECS * 2. A user's code will be valid for a maximum of OTP_LIFETIME_SECS * 2.
        let otp = match otp::generate_otp(
            user.id,
            current_time + env::CONF.lifetimes.otp_lifetime_mins * 60,
        ) {
            Ok(p) => p,
            Err(e) => {
                error!("{}", e);
                return Err(ServerError::InternalError(Some("Failed to generate OTP")));
            }
        };

        // TODO: Don't log this, email it!
        println!("\n\nOTP: {}\n\n", &otp);

        Ok(HttpResponse::Ok().json(signin_token))
    } else {
        Err(ServerError::UserUnauthorized(Some(INVALID_CREDENTIALS_MSG)))
    }
}

pub async fn verify_otp_for_signin(
    db_thread_pool: web::Data<DbThreadPool>,
    otp_and_token: web::Json<SigninTokenOtpPair>,
) -> Result<HttpResponse, ServerError> {
    let token_claims = match web::block(move || {
        jwt::validate_signin_token(&otp_and_token.0.signin_token)
    })
        .await?
    {
        Ok(t) => t,
        Err(e) => match e {
            jwt::JwtError::TokenInvalid => {
                return Err(ServerError::UserUnauthorized(Some("Token is invalid")))
            }
            jwt::JwtError::TokenExpired => {
                return Err(ServerError::UserUnauthorized(Some("Token has expired")))
            }
            jwt::JwtError::WrongTokenType => {
                return Err(ServerError::UserUnauthorized(Some("Incorrect token type")))
            }
            e => {
                error!("{}", e);
                return Err(ServerError::InternalError(Some("Error verifying token")));
            }
        },
    };

    let attempts = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        db::auth::get_and_increment_otp_verification_count(&db_connection, token_claims.uid)
    })
        .await?
    {
        Ok(a) => a,
        Err(e) => {
            error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(
                "Failed to check OTP attempt count",
            )));
        }
    };

    if attempts > env::CONF.security.otp_max_attempts {
        return Err(ServerError::AccessForbidden(Some(
            "Too many attempts. Try again in a few minutes.",
        )));
    }

    let is_valid = match web::block(move || {
        let otp = otp::OneTimePasscode::try_from(otp_and_token.0.otp)?;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_secs();

        let mut is_valid = otp::verify_otp(otp, token_claims.uid, current_time)?;

        // A future code gets sent to the user, so check a current and future code
        if !is_valid {
            is_valid = otp::verify_otp(
                otp,
                token_claims.uid,
                current_time + env::CONF.lifetimes.otp_lifetime_mins * 60,
            )?;
        }

        Ok(is_valid)
    })
        .await?
    {
        Ok(v) => v,
        Err(e) => match e {
            otp::OtpError::Unauthorized => {
                return Err(ServerError::UserUnauthorized(Some("Incorrect passcode")))
            }
            otp::OtpError::ImproperlyFormatted => {
                return Err(ServerError::InputRejected(Some("Invalid passcode")))
            }
            otp::OtpError::Error(_) => {
                error!("{}", e);
                return Err(ServerError::InternalError(Some(
                    "Validating passcode failed",
                )));
            }
        },
    };

    if !is_valid {
        return Err(ServerError::UserUnauthorized(Some("Incorrect passcode")));
    }
    let token_pair = jwt::generate_token_pair(jwt::JwtParams {
        user_id: &token_claims.uid,
        user_email: &token_claims.eml,
        user_currency: &token_claims.cur,
    });

    let token_pair = match token_pair {
        Ok(token_pair) => token_pair,
        Err(e) => {
            error!("{}", e);
            return Err(ServerError::InternalError(Some(
                "Failed to generate tokens for new user",
            )));
        }
    };

    let token_pair = TokenPair {
        access_token: token_pair.access_token.to_string(),
        refresh_token: token_pair.refresh_token.to_string(),
    };

    Ok(HttpResponse::Ok().json(token_pair))
}

pub async fn refresh_tokens(
    db_thread_pool: web::Data<DbThreadPool>,
    token: web::Json<RefreshToken>,
) -> Result<HttpResponse, ServerError> {
    let db_thread_pool_pointer_copy = db_thread_pool.clone();
    let refresh_token = token.0.token.clone();

    let claims = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        jwt::validate_refresh_token(token.0.token.as_str(), &db_connection)
    })
        .await?
    {
        Ok(c) => c,
        Err(e) => match e {
            jwt::JwtError::TokenInvalid => {
                return Err(ServerError::UserUnauthorized(Some("Token is invalid")));
            }
            jwt::JwtError::TokenBlacklisted => {
                return Err(ServerError::UserUnauthorized(Some(
                    "Token has been blacklisted",
                )));
            }
            jwt::JwtError::TokenExpired => {
                return Err(ServerError::UserUnauthorized(Some("Token has expired")));
            }
            jwt::JwtError::WrongTokenType => {
                return Err(ServerError::UserUnauthorized(Some("Incorrect token type")));
            }
            e => {
                error!("{}", e);
                return Err(ServerError::InternalError(Some("Error verifying token")));
            }
        },
    };

    match web::block(move || {
        jwt::blacklist_token(
            refresh_token.as_str(),
            &db_thread_pool_pointer_copy
                .get()
                .expect("Failed to access database thread pool"),
        )
    })
        .await?
    {
        Ok(_) => {}
        Err(e) => {
            error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(
                "Failed to blacklist token",
            )));
        }
    }

    let token_pair = jwt::generate_token_pair(jwt::JwtParams {
        user_id: &claims.uid,
        user_email: &claims.eml,
        user_currency: &claims.cur,
    });

    let token_pair = match token_pair {
        Ok(token_pair) => token_pair,
        Err(e) => {
            error!("{}", e);
            return Err(ServerError::InternalError(Some(
                "Failed to generate tokens for new user",
            )));
        }
    };

    let token_pair = TokenPair {
        access_token: token_pair.access_token.to_string(),
        refresh_token: token_pair.refresh_token.to_string(),
    };

    Ok(HttpResponse::Ok().json(token_pair))
}

pub async fn logout(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    refresh_token: web::Json<RefreshToken>,
) -> Result<HttpResponse, ServerError> {
    let db_thread_pool_pointer_copy = db_thread_pool.clone();
    let refresh_token_copy = refresh_token.token.clone();

    let refresh_token_claims = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        jwt::validate_refresh_token(&refresh_token_copy, &db_connection)
    })
        .await?
    {
        Ok(tc) => tc,
        Err(e) => match e {
            jwt::JwtError::TokenInvalid => {
                return Err(ServerError::UserUnauthorized(Some("Token is invalid")))
            }
            jwt::JwtError::TokenBlacklisted => {
                return Err(ServerError::UserUnauthorized(Some(
                    "Token has been blacklisted",
                )))
            }
            jwt::JwtError::TokenExpired => {
                return Err(ServerError::UserUnauthorized(Some("Token has expired")))
            }
            jwt::JwtError::WrongTokenType => {
                return Err(ServerError::UserUnauthorized(Some("Incorrect token type")))
            }
            e => {
                error!("{}", e);
                return Err(ServerError::InternalError(Some("Error verifying token")));
            }
        },
    };

    if refresh_token_claims.uid != auth_user_claims.0.uid {
        return Err(ServerError::AccessForbidden(Some(
            "Refresh token does not belong to user.",
        )));
    }

    match web::block(move || {
        jwt::blacklist_token(
            refresh_token.0.token.as_str(),
            &db_thread_pool_pointer_copy
                .get()
                .expect("Failed to access database thread pool"),
        )
    })
        .await
    {
        Ok(_) => Ok(HttpResponse::Ok().finish()),
        Err(e) => {
            error!("{}", e);
            Err(ServerError::InternalError(Some(
                "Failed to blacklist token",
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::web::Data;
    use actix_web::{http, test, App};
    use chrono::NaiveDate;
    use rand::prelude::*;

    use crate::env;
    use crate::handlers::request_io::{InputUser, RefreshToken, SigninToken, SigninTokenOtpPair};
    use crate::services;
    use crate::utils::otp;

    #[actix_rt::test]
    async fn test_sign_in() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
            .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
            .await;

        let credentials = CredentialPair {
            email: new_user.email,
            password: new_user.password,
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let signin_token = actix_web::test::read_body_json::<SigninToken, _>(res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        assert!(!signin_token.signin_token.is_empty());

        assert_eq!(
            jwt::validate_signin_token(&signin_token.signin_token)
                .unwrap()
                .uid,
            user_id
        );
    }

    #[actix_rt::test]
    async fn test_sign_in_fails_with_invalid_credentials() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
            .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
            .await;

        let credentials = CredentialPair {
            email: new_user.email.clone(),
            password: new_user.password.clone() + " ",
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_sign_in_fails_after_repeated_attempts() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
            .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
            .await;
        
        let credentials = CredentialPair {
            email: new_user.email,
            password: new_user.password,
        };

        for _ in 0..env::CONF.security.password_max_attempts {
            let req = test::TestRequest::post()
                .uri("/api/auth/sign_in")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
                .to_request();

            let res = test::call_service(&app, req).await;
            assert_eq!(res.status(), http::StatusCode::OK);
        }

        let req = test::TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();
        
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::FORBIDDEN);
    }

    #[actix_rt::test]
    async fn test_verify_otp_with_current_code() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
            .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
            .await;

        let credentials = CredentialPair {
            email: new_user.email,
            password: new_user.password,
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let signin_token = actix_web::test::read_body_json::<SigninToken, _>(res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let otp = otp::generate_otp(user_id, current_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;

        let access_token = token_pair.access_token.to_string();
        let refresh_token = token_pair.refresh_token;

        assert!(!access_token.is_empty());
        assert!(!refresh_token.is_empty());

        let db_connection = db_thread_pool.get().unwrap();

        assert_eq!(
            jwt::validate_access_token(&access_token).unwrap().uid,
            user_id
        );
        assert_eq!(
            jwt::validate_refresh_token(&refresh_token, &db_connection)
                .unwrap()
                .uid,
            user_id
        );
    }

    #[actix_rt::test]
    async fn test_verify_otp_with_next_code() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
            .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
            .await;

        let credentials = CredentialPair {
            email: new_user.email,
            password: new_user.password,
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let signin_token = actix_web::test::read_body_json::<SigninToken, _>(res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + env::CONF.lifetimes.otp_lifetime_mins * 60;

        let otp = otp::generate_otp(user_id, future_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;

        let access_token = token_pair.access_token.to_string();
        let refresh_token = token_pair.refresh_token;

        assert!(!access_token.is_empty());
        assert!(!refresh_token.is_empty());

        let db_connection = db_thread_pool.get().unwrap();

        assert_eq!(
            jwt::validate_access_token(&access_token).unwrap().uid,
            user_id
        );
        assert_eq!(
            jwt::validate_refresh_token(&refresh_token, &db_connection)
                .unwrap()
                .uid,
            user_id
        );
    }

    #[actix_rt::test]
    async fn test_verify_otp_fails_after_repeated_attempts() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
            .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
            .await;

        let credentials = CredentialPair {
            email: new_user.email,
            password: new_user.password,
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let signin_token = actix_web::test::read_body_json::<SigninToken, _>(res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + env::CONF.lifetimes.otp_lifetime_mins * 60;

        let otp = otp::generate_otp(user_id, future_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        for _ in 0..env::CONF.security.otp_max_attempts {
            let req = test::TestRequest::post()
                .uri("/api/auth/verify_otp_for_signin")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
                .to_request();

            let res = test::call_service(&app, req).await;
            assert_eq!(res.status(), http::StatusCode::OK);
        }

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::FORBIDDEN);
    }

    #[actix_rt::test]
    async fn test_verify_otp_fails_with_wrong_code() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
            .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
            .await;

        let credentials = CredentialPair {
            email: new_user.email,
            password: new_user.password,
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let signin_token = actix_web::test::read_body_json::<SigninToken, _>(res).await;

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: String::from("1234 5678"),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_verify_otp_fails_with_expired_code() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
            .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
            .await;

        let credentials = CredentialPair {
            email: new_user.email,
            password: new_user.password,
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let signin_token = actix_web::test::read_body_json::<SigninToken, _>(res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let past_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - env::CONF.lifetimes.otp_lifetime_mins * 60;

        let otp = otp::generate_otp(user_id, past_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_verify_otp_fails_with_future_not_next_code() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
            .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
            .await;

        let credentials = CredentialPair {
            email: new_user.email,
            password: new_user.password,
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let signin_token = actix_web::test::read_body_json::<SigninToken, _>(res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let far_future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + (2 * env::CONF.lifetimes.otp_lifetime_mins * 60);

        let otp = otp::generate_otp(user_id, far_future_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_verify_otp_fails_with_wrong_token() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
            .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
            .await;

        let credentials = CredentialPair {
            email: new_user.email,
            password: new_user.password,
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let signin_token = actix_web::test::read_body_json::<SigninToken, _>(res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let otp = otp::generate_otp(user_id, current_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token + "i",
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_refresh_tokens() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
            .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        let db_connection = db_thread_pool.get().unwrap();

        let create_user_res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
            .await;

        let signin_token = test::read_body_json::<SigninToken, _>(create_user_res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(user_id, current_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;

        let refresh_token_payload = RefreshToken {
            token: token_pair.refresh_token.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/refresh_tokens")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&refresh_token_payload).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;

        let access_token = token_pair.access_token.to_string();
        let refresh_token = token_pair.refresh_token;

        assert!(!access_token.is_empty());
        assert!(!refresh_token.is_empty());

        assert!(jwt::is_on_blacklist(&refresh_token_payload.token, &db_connection).unwrap());
        assert_eq!(
            jwt::validate_access_token(&access_token).unwrap().uid,
            user_id
        );
        assert_eq!(
            jwt::validate_refresh_token(&refresh_token, &db_connection)
                .unwrap()
                .uid,
            user_id
        );
    }

    #[actix_rt::test]
    async fn test_refresh_tokens_fails_with_invalid_refresh_token() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
            .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        let create_user_res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
            .await;

        let signin_token = test::read_body_json::<SigninToken, _>(create_user_res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(user_id, current_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;

        let refresh_token_payload = RefreshToken {
            token: token_pair.refresh_token.to_string() + "e",
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/refresh_tokens")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&refresh_token_payload).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_refresh_tokens_fails_with_access_token() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
            .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        let create_user_res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
            .await;

        let signin_token = test::read_body_json::<SigninToken, _>(create_user_res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(user_id, current_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;

        let refresh_token_payload = RefreshToken {
            token: token_pair.access_token.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/refresh_tokens")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&refresh_token_payload).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_logout() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
            .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        let create_user_res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
            .await;

        let signin_token = test::read_body_json::<SigninToken, _>(create_user_res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(user_id, current_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;

        let logout_payload = RefreshToken {
            token: token_pair.refresh_token.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/logout")
            .insert_header(("content-type", "application/json"))
            .insert_header((
                "authorization",
                format!("Bearer {}", &token_pair.access_token),
            ))
            .set_payload(serde_json::ser::to_vec(&logout_payload).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let db_connection = db_thread_pool.get().unwrap();
        assert!(jwt::is_on_blacklist(&logout_payload.token, &db_connection).unwrap());
    }

    #[actix_rt::test]
    async fn test_logout_fails_with_invalid_refresh_token() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
            .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        let create_user_res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
            .await;

        let signin_token = test::read_body_json::<SigninToken, _>(create_user_res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(user_id, current_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;

        let logout_payload = RefreshToken {
            token: token_pair.refresh_token.to_string() + "f",
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/logout")
            .insert_header(("content-type", "application/json"))
            .insert_header((
                "authorization",
                format!("Bearer {}", &token_pair.access_token),
            ))
            .set_payload(serde_json::ser::to_vec(&logout_payload).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);

        let db_connection = db_thread_pool.get().unwrap();
        assert!(!jwt::is_on_blacklist(&logout_payload.token, &db_connection).unwrap());
    }
}
