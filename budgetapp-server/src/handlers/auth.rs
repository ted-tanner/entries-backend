use budgetapp_utils::db::DbThreadPool;
use budgetapp_utils::request_io::{
    CredentialPair, RefreshToken, SigninToken, SigninTokenOtpPair, TokenPair,
};
use budgetapp_utils::{auth_token, db, otp, password_hasher};

use actix_web::{web, HttpResponse};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::env;
use crate::handlers::error::ServerError;
use crate::middleware;

pub async fn sign_in(
    db_thread_pool: web::Data<DbThreadPool>,
    credentials: web::Json<CredentialPair>,
) -> Result<HttpResponse, ServerError> {
    const INVALID_CREDENTIALS_MSG: &str = "Incorrect email or password";

    if !credentials.validate_email_address().is_valid() {
        return Err(ServerError::InvalidFormat(Some(String::from(
            "Invalid email address",
        ))));
    }

    let user_email = credentials.email.clone();
    let mut user_dao = db::user::Dao::new(&db_thread_pool);

    let user = match web::block(move || user_dao.get_user_by_email(&user_email)).await? {
        Ok(u) => u,
        Err(_) => {
            return Err(ServerError::UserUnauthorized(Some(String::from(
                INVALID_CREDENTIALS_MSG,
            ))))
        }
    };

    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);

    let attempts = match web::block(move || {
        auth_dao.get_and_increment_password_attempt_count(
            user.id,
            Duration::from_secs(env::CONF.security.password_attempts_reset_mins * 60),
        )
    })
    .await?
    {
        Ok(a) => a,
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to check password attempt count",
            ))));
        }
    };

    if attempts.attempt_count > env::CONF.security.password_max_attempts
        && attempts.expiration_time >= SystemTime::now()
    {
        return Err(ServerError::AccessForbidden(Some(String::from(
            "Too many login attempts. Try again in a few minutes.",
        ))));
    }

    let does_password_match_hash = web::block(move || {
        password_hasher::verify_hash(
            &credentials.password,
            &user.password_hash,
            env::CONF.keys.hashing_key.as_bytes(),
        )
    })
    .await?;

    if does_password_match_hash {
        let signin_token = auth_token::generate_signin_token(
            &auth_token::TokenParams {
                user_id: &user.id,
                user_email: &user.email,
                user_currency: &user.currency,
            },
            Duration::from_secs(env::CONF.lifetimes.access_token_lifetime_mins * 60),
            env::CONF.keys.token_signing_key.as_bytes(),
        );

        let signin_token = match signin_token {
            Ok(signin_token) => signin_token,
            Err(e) => {
                log::error!("{}", e);
                return Err(ServerError::InternalError(Some(String::from(
                    "Failed to generate sign-in token for user",
                ))));
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
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        ) {
            Ok(p) => p,
            Err(e) => {
                log::error!("{}", e);
                return Err(ServerError::InternalError(Some(String::from(
                    "Failed to generate OTP",
                ))));
            }
        };

        // TODO: Don't log this, email it!
        println!("\n\nOTP: {}\n\n", &otp);

        Ok(HttpResponse::Ok().json(signin_token))
    } else {
        Err(ServerError::UserUnauthorized(Some(String::from(
            INVALID_CREDENTIALS_MSG,
        ))))
    }
}

pub async fn verify_otp_for_signin(
    db_thread_pool: web::Data<DbThreadPool>,
    otp_and_token: web::Json<SigninTokenOtpPair>,
) -> Result<HttpResponse, ServerError> {
    let token_claims = match web::block(move || {
        auth_token::validate_signin_token(
            &otp_and_token.0.signin_token,
            env::CONF.keys.token_signing_key.as_bytes(),
        )
    })
    .await?
    {
        Ok(t) => t,
        Err(e) => match e {
            auth_token::TokenError::TokenInvalid => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token is invalid",
                ))));
            }
            auth_token::TokenError::TokenExpired => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token has expired",
                ))));
            }
            auth_token::TokenError::TokenBlacklisted => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token has been blacklisted",
                ))));
            }
            auth_token::TokenError::WrongTokenType => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Incorrect token type",
                ))));
            }
            e => {
                log::error!("{}", e);
                return Err(ServerError::InternalError(Some(String::from(
                    "Error verifying token",
                ))));
            }
        },
    };

    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);

    let attempts = match web::block(move || {
        auth_dao.get_and_increment_otp_verification_count(
            token_claims.uid,
            Duration::from_secs(env::CONF.security.otp_attempts_reset_mins * 60),
        )
    })
    .await?
    {
        Ok(a) => a,
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to check OTP attempt count",
            ))));
        }
    };

    if attempts.attempt_count > env::CONF.security.otp_max_attempts
        && attempts.expiration_time >= SystemTime::now()
    {
        return Err(ServerError::AccessForbidden(Some(String::from(
            "Too many attempts. Try again in a few minutes.",
        ))));
    }

    let is_valid = match web::block(move || {
        let otp = otp::OneTimePasscode::try_from(otp_and_token.0.otp)?;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_secs();

        let mut is_valid = otp::verify_otp(
            otp,
            token_claims.uid,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )?;

        // A future code gets sent to the user, so check a current and future code
        if !is_valid {
            is_valid = otp::verify_otp(
                otp,
                token_claims.uid,
                current_time + env::CONF.lifetimes.otp_lifetime_mins * 60,
                Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
                env::CONF.keys.otp_key.as_bytes(),
            )?;
        }

        Ok(is_valid)
    })
    .await?
    {
        Ok(v) => v,
        Err(e) => match e {
            otp::OtpError::Unauthorized => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Incorrect passcode",
                ))))
            }
            otp::OtpError::ImproperlyFormatted => {
                return Err(ServerError::InputRejected(Some(String::from(
                    "Invalid passcode",
                ))))
            }
            otp::OtpError::Error(_) => {
                log::error!("{}", e);
                return Err(ServerError::InternalError(Some(String::from(
                    "Validating passcode failed",
                ))));
            }
        },
    };

    if !is_valid {
        return Err(ServerError::UserUnauthorized(Some(String::from(
            "Incorrect passcode",
        ))));
    }

    let token_pair = auth_token::generate_token_pair(
        &auth_token::TokenParams {
            user_id: &token_claims.uid,
            user_email: &token_claims.eml,
            user_currency: &token_claims.cur,
        },
        Duration::from_secs(env::CONF.lifetimes.access_token_lifetime_mins * 60),
        Duration::from_secs(env::CONF.lifetimes.refresh_token_lifetime_days * 60 * 60 * 24),
        env::CONF.keys.token_signing_key.as_bytes(),
    );

    let token_pair = match token_pair {
        Ok(token_pair) => token_pair,
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::InternalError(Some(String::from(
                "Failed to generate tokens for new user",
            ))));
        }
    };

    let token_pair = TokenPair {
        access_token: token_pair.access_token.to_string(),
        refresh_token: token_pair.refresh_token.to_string(),
    };

    let mut user_dao = db::user::Dao::new(&db_thread_pool);

    // TODO: Test this
    // TODO: Make it so users don't have to wait for this
    match web::block(move || user_dao.set_last_token_refresh_now(token_claims.uid)).await? {
        Ok(_) => (),
        Err(e) => log::error!("{}", e),
    };

    Ok(HttpResponse::Ok().json(token_pair))
}

pub async fn refresh_tokens(
    db_thread_pool: web::Data<DbThreadPool>,
    token: web::Json<RefreshToken>,
) -> Result<HttpResponse, ServerError> {
    let refresh_token = token.0.token.clone();
    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);

    let claims = match web::block(move || {
        auth_token::validate_refresh_token(
            token.0.token.as_str(),
            env::CONF.keys.token_signing_key.as_bytes(),
            &mut auth_dao,
        )
    })
    .await?
    {
        Ok(c) => c,
        Err(e) => match e {
            auth_token::TokenError::TokenInvalid => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token is invalid",
                ))));
            }
            auth_token::TokenError::TokenBlacklisted => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token has been blacklisted",
                ))));
            }
            auth_token::TokenError::TokenExpired => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token has expired",
                ))));
            }
            auth_token::TokenError::WrongTokenType => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Incorrect token type",
                ))));
            }
            e => {
                log::error!("{}", e);
                return Err(ServerError::InternalError(Some(String::from(
                    "Error verifying token",
                ))));
            }
        },
    };

    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);

    // TODO: Make it so users don't have to wait for this
    match web::block(move || auth_token::blacklist_token(refresh_token.as_str(), &mut auth_dao))
        .await?
    {
        Ok(_) => {}
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to blacklist token",
            ))));
        }
    }

    let token_pair = auth_token::generate_token_pair(
        &auth_token::TokenParams {
            user_id: &claims.uid,
            user_email: &claims.eml,
            user_currency: &claims.cur,
        },
        Duration::from_secs(env::CONF.lifetimes.access_token_lifetime_mins * 60),
        Duration::from_secs(env::CONF.lifetimes.refresh_token_lifetime_days * 60 * 60 * 24),
        env::CONF.keys.token_signing_key.as_bytes(),
    );

    let token_pair = match token_pair {
        Ok(token_pair) => token_pair,
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::InternalError(Some(String::from(
                "Failed to generate tokens for new user",
            ))));
        }
    };

    let token_pair = TokenPair {
        access_token: token_pair.access_token.to_string(),
        refresh_token: token_pair.refresh_token.to_string(),
    };

    let mut user_dao = db::user::Dao::new(&db_thread_pool);

    // TODO: Test this
    // TODO: Make it so users don't have to wait for this
    match web::block(move || user_dao.set_last_token_refresh_now(claims.uid)).await? {
        Ok(_) => (),
        Err(e) => log::error!("{}", e),
    };

    Ok(HttpResponse::Ok().json(token_pair))
}

pub async fn logout(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    refresh_token: web::Json<RefreshToken>,
) -> Result<HttpResponse, ServerError> {
    let refresh_token_clone = refresh_token.token.clone();
    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);

    let refresh_token_claims = match web::block(move || {
        auth_token::validate_refresh_token(
            &refresh_token_clone,
            env::CONF.keys.token_signing_key.as_bytes(),
            &mut auth_dao,
        )
    })
    .await?
    {
        Ok(tc) => tc,
        Err(e) => match e {
            auth_token::TokenError::TokenInvalid => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token is invalid",
                ))))
            }
            auth_token::TokenError::TokenBlacklisted => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token has been blacklisted",
                ))))
            }
            auth_token::TokenError::TokenExpired => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token has expired",
                ))))
            }
            auth_token::TokenError::WrongTokenType => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Incorrect token type",
                ))))
            }
            e => {
                log::error!("{}", e);
                return Err(ServerError::InternalError(Some(String::from(
                    "Error verifying token",
                ))));
            }
        },
    };

    if refresh_token_claims.uid != auth_user_claims.0.uid {
        return Err(ServerError::AccessForbidden(Some(String::from(
            "Refresh token does not belong to user.",
        ))));
    }

    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);

    match web::block(move || {
        auth_token::blacklist_token(refresh_token.0.token.as_str(), &mut auth_dao)
    })
    .await
    {
        Ok(_) => Ok(HttpResponse::Ok().finish()),
        Err(e) => {
            log::error!("{}", e);
            Err(ServerError::InternalError(Some(String::from(
                "Failed to blacklist token",
            ))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use budgetapp_utils::auth_token::TokenClaims;
    use budgetapp_utils::models::user::User;
    use budgetapp_utils::otp;
    use budgetapp_utils::request_io::{InputUser, RefreshToken, SigninToken, SigninTokenOtpPair};
    use budgetapp_utils::schema::otp_attempts as otp_attempts_fields;
    use budgetapp_utils::schema::otp_attempts::dsl::otp_attempts;
    use budgetapp_utils::schema::password_attempts as password_attempts_fields;
    use budgetapp_utils::schema::password_attempts::dsl::password_attempts;
    use budgetapp_utils::schema::users as user_fields;
    use budgetapp_utils::schema::users::dsl::users;

    use actix_web::web::Data;
    use actix_web::{http, test, App};
    use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
    use rand::prelude::*;

    use crate::env;
    use crate::services;

    #[actix_rt::test]
    async fn test_sign_in() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        assert!(!signin_token.signin_token.is_empty());

        assert_eq!(
            auth_token::validate_signin_token(
                &signin_token.signin_token,
                env::CONF.keys.token_signing_key.as_bytes()
            )
            .unwrap()
            .uid,
            user_id
        );
    }

    #[actix_rt::test]
    async fn test_password_attempts_expires() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("my_test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
            password: new_user.password,
        };

        let creds_vec = serde_json::ser::to_vec(&credentials).unwrap();

        for _ in 0..env::CONF.security.password_max_attempts {
            let req = test::TestRequest::post()
                .uri("/api/auth/sign_in")
                .insert_header(("content-type", "application/json"))
                .set_payload(creds_vec.clone())
                .to_request();

            let res = test::call_service(&app, req).await;
            assert_eq!(res.status(), http::StatusCode::OK);
        }

        let req = test::TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("content-type", "application/json"))
            .set_payload(creds_vec.clone())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::FORBIDDEN);

        let user_id = users
            .filter(user_fields::email.eq(new_user.email))
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap()
            .id;

        dsl::update(password_attempts.filter(password_attempts_fields::user_id.eq(user_id)))
            .set(
                password_attempts_fields::expiration_time
                    .eq(SystemTime::now() - Duration::from_millis(1)),
            )
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let req = test::TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("content-type", "application/json"))
            .set_payload(creds_vec)
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);
    }

    #[actix_rt::test]
    async fn test_sign_in_fails_with_invalid_credentials() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

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

        let mut auth_dao = db::auth::Dao::new(&env::testing::DB_THREAD_POOL);

        assert_eq!(
            auth_token::validate_access_token(
                &access_token,
                env::CONF.keys.token_signing_key.as_bytes()
            )
            .unwrap()
            .uid,
            user_id
        );
        assert_eq!(
            auth_token::validate_refresh_token(
                &refresh_token,
                env::CONF.keys.token_signing_key.as_bytes(),
                &mut auth_dao
            )
            .unwrap()
            .uid,
            user_id
        );
    }

    #[actix_rt::test]
    async fn test_otp_attempts_expires() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let creds_vec = serde_json::ser::to_vec(&token_and_otp).unwrap();

        for _ in 0..env::CONF.security.otp_max_attempts {
            let req = test::TestRequest::post()
                .uri("/api/auth/verify_otp_for_signin")
                .insert_header(("content-type", "application/json"))
                .set_payload(creds_vec.clone())
                .to_request();

            let res = test::call_service(&app, req).await;
            assert_eq!(res.status(), http::StatusCode::OK);
        }

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(creds_vec.clone())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::FORBIDDEN);

        let user_id = users
            .filter(user_fields::email.eq(new_user.email))
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap()
            .id;

        dsl::update(otp_attempts.filter(otp_attempts_fields::user_id.eq(user_id)))
            .set(
                otp_attempts_fields::expiration_time
                    .eq(SystemTime::now() - Duration::from_millis(1)),
            )
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(creds_vec.clone())
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);
    }

    #[actix_rt::test]
    async fn test_verify_otp_with_next_code() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + env::CONF.lifetimes.otp_lifetime_mins * 60;

        let otp = otp::generate_otp(
            user_id,
            future_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

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

        let mut auth_dao = db::auth::Dao::new(&env::testing::DB_THREAD_POOL);

        assert_eq!(
            auth_token::validate_access_token(
                &access_token,
                env::CONF.keys.token_signing_key.as_bytes()
            )
            .unwrap()
            .uid,
            user_id
        );
        assert_eq!(
            auth_token::validate_refresh_token(
                &refresh_token,
                env::CONF.keys.token_signing_key.as_bytes(),
                &mut auth_dao
            )
            .unwrap()
            .uid,
            user_id
        );
    }

    #[actix_rt::test]
    async fn test_verify_otp_fails_after_repeated_attempts() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + env::CONF.lifetimes.otp_lifetime_mins * 60;

        let otp = otp::generate_otp(
            user_id,
            future_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

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
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let past_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - env::CONF.lifetimes.otp_lifetime_mins * 60;

        let otp = otp::generate_otp(
            user_id,
            past_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

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
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let far_future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + (2 * env::CONF.lifetimes.otp_lifetime_mins * 60);

        let otp = otp::generate_otp(
            user_id,
            far_future_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

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
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

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
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

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

        let mut auth_dao = db::auth::Dao::new(&env::testing::DB_THREAD_POOL);

        assert!(auth_token::is_on_blacklist(&refresh_token_payload.token, &mut auth_dao).unwrap());
        assert_eq!(
            auth_token::validate_access_token(
                &access_token,
                env::CONF.keys.token_signing_key.as_bytes()
            )
            .unwrap()
            .uid,
            user_id
        );
        assert_eq!(
            auth_token::validate_refresh_token(
                &refresh_token,
                env::CONF.keys.token_signing_key.as_bytes(),
                &mut auth_dao
            )
            .unwrap()
            .uid,
            user_id
        );
    }

    #[actix_rt::test]
    async fn test_refresh_tokens_fails_with_invalid_refresh_token() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

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
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

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
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

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

        let mut auth_dao = db::auth::Dao::new(&env::testing::DB_THREAD_POOL);
        assert!(auth_token::is_on_blacklist(&logout_payload.token, &mut auth_dao).unwrap());
    }

    #[actix_rt::test]
    async fn test_logout_fails_with_invalid_refresh_token() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
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
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

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

        let mut auth_dao = db::auth::Dao::new(&env::testing::DB_THREAD_POOL);
        assert!(!auth_token::is_on_blacklist(&logout_payload.token, &mut auth_dao).unwrap());
    }
}
