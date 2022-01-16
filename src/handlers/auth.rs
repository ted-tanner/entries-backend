use actix_web::{web, HttpResponse};
use log::error;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::db_utils;
use crate::definitions::DbThreadPool;
use crate::env;
use crate::handlers::error::ServerError;
use crate::handlers::request_io::{
    CredentialPair, RefreshToken, SigninToken, SigninTokenOtpPair, TokenPair,
};
use crate::utils::{jwt, otp, password_hasher};

pub async fn sign_in(
    db_thread_pool: web::Data<DbThreadPool>,
    credentials: web::Json<CredentialPair>,
) -> Result<HttpResponse, ServerError> {
    const INVALID_CREDENTIALS_MSG: &'static str = "Incorrect email or password";

    if !credentials.validate_email_address().is_valid() {
        return Err(ServerError::InvalidFormat(Some("Invalid email address")));
    }

    let password = credentials.password.clone();

    let user = web::block(move || {
        let db_connection = db_thread_pool.get().expect("Failed to access thread pool");
        db_utils::user::get_user_by_email(&db_connection, &credentials.email)
    })
    .await
    .map_err(|_| Err(ServerError::UserUnauthorized(Some(INVALID_CREDENTIALS_MSG))))?;

    let does_password_match_hash = web::block(move || {
        Ok(password_hasher::verify_hash(&password, &user.password_hash))
            .map_err(|_: ServerError| ServerError::InternalServerError(None))
    })
    .await
    .expect("Failed to block on password verification");

    if does_password_match_hash {
        let signin_token = jwt::generate_signin_token(jwt::JwtParams {
            user_id: &user.id,
            user_email: &user.email,
            user_currency: &user.currency,
        });

        let signin_token = match signin_token {
            Ok(signin_token) => signin_token,
            Err(_) => {
                return Err(ServerError::InternalServerError(Some(
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
            &user.id,
            &current_time + env::CONF.lifetimes.otp_lifetime_mins * 60,
        ) {
            Ok(p) => p,
            Err(_) => {
                return Err(ServerError::InternalServerError(Some(
                    "Failed to generate OTP",
                )))
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
    otp_and_token: web::Json<SigninTokenOtpPair>,
) -> Result<HttpResponse, ServerError> {
    let token_claims =
        web::block(move || jwt::validate_signin_token(&otp_and_token.0.signin_token))
            .await
            .map_err(|e| match e {
                actix_web::error::BlockingError::Error(err) => match err {
                    jwt::JwtError::TokenInvalid => {
                        return Err(ServerError::UserUnauthorized(Some("Token is invalid")))
                    }
                    jwt::JwtError::TokenExpired => {
                        return Err(ServerError::UserUnauthorized(Some("Token has expired")))
                    }
                    jwt::JwtError::WrongTokenType => {
                        return Err(ServerError::UserUnauthorized(Some("Incorrect token type")))
                    }
                    _ => {
                        return Err(ServerError::InternalServerError(Some(
                            "Error verifying token",
                        )))
                    }
                },
                actix_web::error::BlockingError::Canceled => {
                    return Err(ServerError::InternalServerError(Some("Response canceled")))
                }
            })?;

    web::block(move || {
        // TODO: If this fails, check with system time + OTP_LIFETIME_SECS
        let otp = otp::OneTimePasscode::try_from(otp_and_token.0.otp)?;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_secs();

        let mut is_valid = otp::verify_otp(otp, &token_claims.uid, current_time)?;

        // A future code gets sent to the user, so check a current and future code
        if !is_valid {
            is_valid = otp::verify_otp(
                otp,
                &token_claims.uid,
                current_time + env::CONF.lifetimes.otp_lifetime_mins * 60,
            )?;
        }

        Ok(is_valid)
    })
    .await
    .map(|is_valid| {
        if is_valid {
            let token_pair = jwt::generate_token_pair(jwt::JwtParams {
                user_id: &token_claims.uid,
                user_email: &token_claims.eml,
                user_currency: &token_claims.cur,
            });

            let token_pair = match token_pair {
                Ok(token_pair) => token_pair,
                Err(e) => {
                    error!("{}", e);

                    return Err(ServerError::InternalServerError(Some(
                        "Failed to generate tokens for new user",
                    )));
                }
            };

            let token_pair = TokenPair {
                access_token: token_pair.access_token.to_string(),
                refresh_token: token_pair.refresh_token.to_string(),
            };

            Ok(HttpResponse::Ok().json(token_pair))
        } else {
            Err(ServerError::UserUnauthorized(Some("Incorrect passcode")))
        }
    })
    .map_err(|e| match e {
        actix_web::error::BlockingError::Error(err) => match err {
            otp::OtpError::Unauthorized => {
                Err(ServerError::UserUnauthorized(Some("Incorrect passcode")))
            }
            otp::OtpError::ImproperlyFormatted => {
                Err(ServerError::InputRejected(Some("Invalid passcode")))
            }
            otp::OtpError::Error(_) => Err(ServerError::InternalServerError(Some(
                "Validating passcode failed",
            ))),
        },
        actix_web::error::BlockingError::Canceled => {
            return Err(ServerError::InternalServerError(Some("Response canceled")))
        }
    })?
}

pub async fn refresh_tokens(
    db_thread_pool: web::Data<DbThreadPool>,
    token: web::Json<RefreshToken>,
) -> Result<HttpResponse, ServerError> {
    let refresh_token = &token.0.token.clone();
    let db_connection = &db_thread_pool.get().expect("Failed to access thread pool");

    web::block(move || {
        jwt::validate_refresh_token(
            token.0.token.as_str(),
            &db_thread_pool.get().expect("Failed to access thread pool"),
        )
    })
    .await
    .map(|claims| {
        match jwt::blacklist_token(refresh_token.as_str(), db_connection) {
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

                return Err(ServerError::InternalServerError(Some(
                    "Failed to generate tokens for new user",
                )));
            }
        };

        let token_pair = TokenPair {
            access_token: token_pair.access_token.to_string(),
            refresh_token: token_pair.refresh_token.to_string(),
        };

        Ok(HttpResponse::Ok().json(token_pair))
    })
    .map_err(|e| {
        Err(match e {
            actix_web::error::BlockingError::Error(err) => match err {
                jwt::JwtError::TokenInvalid => {
                    ServerError::UserUnauthorized(Some("Token is invalid"))
                }
                jwt::JwtError::TokenBlacklisted => {
                    ServerError::UserUnauthorized(Some("Token has been blacklisted"))
                }
                jwt::JwtError::TokenExpired => {
                    ServerError::UserUnauthorized(Some("Token has expired"))
                }
                jwt::JwtError::WrongTokenType => {
                    ServerError::UserUnauthorized(Some("Incorrect token type"))
                }
                _ => ServerError::InternalServerError(Some("Error verifying token")),
            },
            actix_web::error::BlockingError::Canceled => {
                ServerError::InternalServerError(Some("Response canceled"))
            }
        })
    })?
}

pub async fn logout(
    db_thread_pool: web::Data<DbThreadPool>,
    refresh_token: web::Json<RefreshToken>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        // TODO: REQUIRE ACCESS TOKEN
        // TODO: VALIDATE THE TOKEN FOR THE USER FIRST!!!
        // TODO: Test that logout fails if token is invalid
        jwt::blacklist_token(
            refresh_token.0.token.as_str(),
            &db_thread_pool.get().expect("Failed to access thread pool"),
        )
    })
    .await
    {
        Ok(_) => Ok(HttpResponse::Ok().finish()),
        Err(_) => Err(ServerError::InternalServerError(Some(
            "Failed to blacklist token",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::{http, test, App};
    use chrono::NaiveDate;
    use rand::prelude::*;

    use crate::env;
    use crate::handlers::request_io::{InputUser, RefreshToken, SigninToken, SigninTokenOtpPair};
    use crate::services;
    use crate::utils::otp;

    #[actix_rt::test]
    async fn test_sign_in() {
        let db_thread_pool = &*env::testing::THREAD_POOL;

        let mut app = test::init_service(
            App::new()
                .data(db_thread_pool.clone())
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
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
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let signin_token = actix_web::test::read_body_json::<SigninToken, _>(res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        assert!(signin_token.signin_token.len() > 0);

        assert_eq!(
            jwt::validate_signin_token(&signin_token.signin_token)
                .unwrap()
                .uid,
            user_id
        );
    }

    #[actix_rt::test]
    async fn test_sign_in_fails_with_invalid_credentials() {
        let db_thread_pool = &*env::testing::THREAD_POOL;

        let mut app = test::init_service(
            App::new()
                .data(db_thread_pool.clone())
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
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
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_verify_otp_with_current_code() {
        let db_thread_pool = &*env::testing::THREAD_POOL;

        let mut app = test::init_service(
            App::new()
                .data(db_thread_pool.clone())
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
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
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let signin_token = actix_web::test::read_body_json::<SigninToken, _>(res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let otp = otp::generate_otp(&user_id, current_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;

        let access_token = token_pair.access_token.to_string();
        let refresh_token = token_pair.refresh_token.to_string();

        assert!(access_token.len() > 0);
        assert!(refresh_token.len() > 0);

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
        let db_thread_pool = &*env::testing::THREAD_POOL;

        let mut app = test::init_service(
            App::new()
                .data(db_thread_pool.clone())
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
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
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let signin_token = actix_web::test::read_body_json::<SigninToken, _>(res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + env::CONF.lifetimes.otp_lifetime_mins * 60;

        let otp = otp::generate_otp(&user_id, future_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;

        let access_token = token_pair.access_token.to_string();
        let refresh_token = token_pair.refresh_token.to_string();

        assert!(access_token.len() > 0);
        assert!(refresh_token.len() > 0);

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
    async fn test_verify_otp_fails_with_wrong_code() {
        let db_thread_pool = &*env::testing::THREAD_POOL;

        let mut app = test::init_service(
            App::new()
                .data(db_thread_pool.clone())
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
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
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let signin_token = actix_web::test::read_body_json::<SigninToken, _>(res).await;

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: String::from("1234 5678"),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_verify_otp_fails_with_expired_code() {
        let db_thread_pool = &*env::testing::THREAD_POOL;

        let mut app = test::init_service(
            App::new()
                .data(db_thread_pool.clone())
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
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
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let signin_token = actix_web::test::read_body_json::<SigninToken, _>(res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let past_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - env::CONF.lifetimes.otp_lifetime_mins * 60;

        let otp = otp::generate_otp(&user_id, past_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_verify_otp_fails_with_future_not_next_code() {
        let db_thread_pool = &*env::testing::THREAD_POOL;

        let mut app = test::init_service(
            App::new()
                .data(db_thread_pool.clone())
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
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
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let signin_token = actix_web::test::read_body_json::<SigninToken, _>(res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let far_future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + (2 * env::CONF.lifetimes.otp_lifetime_mins * 60);

        let otp = otp::generate_otp(&user_id, far_future_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_verify_otp_fails_with_wrong_token() {
        let db_thread_pool = &*env::testing::THREAD_POOL;

        let mut app = test::init_service(
            App::new()
                .data(db_thread_pool.clone())
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
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
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&credentials).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let signin_token = actix_web::test::read_body_json::<SigninToken, _>(res).await;
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let otp = otp::generate_otp(&user_id, current_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token + "i",
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_refresh_tokens() {
        let db_thread_pool = &*env::testing::THREAD_POOL;

        let mut app = test::init_service(
            App::new()
                .data(db_thread_pool.clone())
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
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
        let otp = otp::generate_otp(&user_id, current_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;

        let refresh_token_payload = RefreshToken {
            token: token_pair.refresh_token.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/refresh_tokens")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&refresh_token_payload).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;

        let access_token = token_pair.access_token.to_string();
        let refresh_token = token_pair.refresh_token.to_string();

        assert!(access_token.len() > 0);
        assert!(refresh_token.len() > 0);

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
        let db_thread_pool = &*env::testing::THREAD_POOL;

        let mut app = test::init_service(
            App::new()
                .data(db_thread_pool.clone())
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
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
        let otp = otp::generate_otp(&user_id, current_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;

        let refresh_token_payload = RefreshToken {
            token: token_pair.refresh_token.to_string() + "e",
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/refresh_tokens")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&refresh_token_payload).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_refresh_tokens_fails_with_access_token() {
        let db_thread_pool = &*env::testing::THREAD_POOL;

        let mut app = test::init_service(
            App::new()
                .data(db_thread_pool.clone())
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
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
        let otp = otp::generate_otp(&user_id, current_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;

        let refresh_token_payload = RefreshToken {
            token: token_pair.access_token.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/refresh_tokens")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&refresh_token_payload).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_logout() {
        let db_thread_pool = &*env::testing::THREAD_POOL;

        let mut app = test::init_service(
            App::new()
                .data(db_thread_pool.clone())
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
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
        let otp = otp::generate_otp(&user_id, current_time).unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;

        let logout_payload = RefreshToken {
            token: token_pair.refresh_token.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/logout")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&logout_payload).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let db_connection = db_thread_pool.get().unwrap();
        assert!(jwt::is_on_blacklist(&logout_payload.token, &db_connection).unwrap());
    }
}
