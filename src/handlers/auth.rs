use std::str::FromStr;

use actix_web::{web, HttpResponse};
use log::error;

use crate::db_utils;
use crate::definitions::ThreadPool;
use crate::handlers::error::ServerError;
use crate::handlers::request_io::CredentialPair;
use crate::handlers::request_io::RefreshToken;
use crate::utils::jwt;
use crate::utils::password_hasher;

pub async fn sign_in(
    thread_pool: web::Data<ThreadPool>,
    credentials: web::Json<CredentialPair>,
) -> Result<HttpResponse, ServerError> {
    const INVALID_CREDENTIALS_MSG: &'static str = "Incorrect email or password";

    if !credentials.validate_email_address() {
        return Err(ServerError::InvalidFormat(Some("Invalid email address")));
    }

    let password = credentials.password.clone();

    web::block(move || {
        let db_connection = thread_pool.get().expect("Failed to access thread pool");
        db_utils::user::get_user_by_email(&db_connection, &credentials.email)
    })
    .await
    .map(
        |user| match password_hasher::verify_hash(&password, &user.password_hash) {
            true => {
                let token_pair = jwt::generate_token_pair(&user.id);

                let token_pair = match token_pair {
                    Ok(token_pair) => token_pair,
                    Err(_) => {
                        return Err(ServerError::InternalServerError(Some(
                            "Failed to generate tokens for new user. User has been created.",
                        )));
                    }
                };

                Ok(HttpResponse::Ok().json(token_pair))
            }
            false => return Err(ServerError::UserUnauthorized(Some(INVALID_CREDENTIALS_MSG))),
        },
    )
    .map_err(|_| {
        // Hash the provided password and generate a token pair unnecessarily so attackers
        // can't tell the difference between an incorrect password and a non-existent email

        let password = if password.len() == 0 { " " } else { &password };

        password_hasher::hash_argon2id(password);
        jwt::generate_token_pair(
            &uuid::Uuid::from_str("00000000-0000-0000-0000-000000000000")
                .expect("Failed to parse an all-zero UUID"),
        )
        .unwrap_or(jwt::TokenPair::empty());

        Err(ServerError::UserUnauthorized(Some(INVALID_CREDENTIALS_MSG)))
    })?
}

pub async fn refresh_tokens(
    thread_pool: web::Data<ThreadPool>,
    token: web::Json<RefreshToken>,
) -> Result<HttpResponse, ServerError> {
    let refresh_token = &token.0 .0.clone();
    let db_connection = &thread_pool.get().expect("Failed to access thread pool");

    web::block(move || {
        jwt::validate_refresh_token(
            token.0 .0.as_str(),
            &thread_pool.get().expect("Failed to access thread pool"),
        )
    })
    .await
    .map(|claims| {
        let user_id = claims.uid;

        match jwt::blacklist_token(refresh_token.as_str(), db_connection) {
            Ok(_) => {}
            Err(e) => {
                error!("{}", e);

                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to blacklist token",
                )));
            }
        }

        let token_pair = jwt::generate_token_pair(&user_id);

        let token_pair = match token_pair {
            Ok(token_pair) => token_pair,
            Err(e) => {
                error!("{}", e);

                return Err(ServerError::InternalServerError(Some(
                    "Failed to generate tokens for new user",
                )));
            }
        };

        Ok(HttpResponse::Ok().json(token_pair))
    })
    .map_err(|e| {
        Err(match e {
            actix_web::error::BlockingError::Error(err) => match err.kind() {
                jwt::ErrorKind::TokenInvalid => {
                    ServerError::UserUnauthorized(Some("Token is invalid"))
                }
                jwt::ErrorKind::TokenBlacklisted => {
                    ServerError::UserUnauthorized(Some("Token has been blacklisted"))
                }
                jwt::ErrorKind::TokenExpired => {
                    ServerError::UserUnauthorized(Some("Token has expired"))
                }
                jwt::ErrorKind::WrongTokenType => {
                    ServerError::UserUnauthorized(Some("Incorrect token type"))
                }
                _ => ServerError::InternalServerError(Some("Error generating new tokens")),
            },
            actix_web::error::BlockingError::Canceled => {
                ServerError::InternalServerError(Some("Response canceled"))
            }
        })
    })?
}

pub async fn logout(
    thread_pool: web::Data<ThreadPool>,
    refresh_token: web::Json<RefreshToken>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        jwt::blacklist_token(
            refresh_token.0 .0.as_str(),
            &thread_pool.get().expect("Failed to access thread pool"),
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
    use diesel::prelude::*;
    use diesel::r2d2::{self, ConnectionManager};
    use rand::prelude::*;

    use crate::env;
    use crate::handlers::request_io::InputUser;
    use crate::handlers::request_io::RefreshToken;
    use crate::handlers::user;
    use crate::utils::jwt;

    #[actix_rt::test]
    async fn test_sign_in() {
        let manager = ConnectionManager::<PgConnection>::new(env::db::DATABASE_URL.as_str());
        let thread_pool = r2d2::Pool::builder().build(manager).unwrap();

        let mut app = test::init_service(
            App::new()
                .data(thread_pool.clone())
                .route("/api/user/create", web::post().to(user::create))
                .route("/api/auth/sign_in", web::post().to(sign_in)),
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

        let db_connection = thread_pool.get().unwrap();

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

        let token_pair = actix_web::test::read_body_json::<jwt::TokenPair, _>(res).await;

        let access_token = token_pair.access_token.to_string();
        let refresh_token = token_pair.refresh_token.to_string();

        let user_id = jwt::read_claims(&access_token).unwrap().uid;

        assert!(access_token.len() > 0);
        assert!(refresh_token.len() > 0);

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
    async fn test_refresh_tokens() {
        let manager = ConnectionManager::<PgConnection>::new(env::db::DATABASE_URL.as_str());
        let thread_pool = r2d2::Pool::builder().build(manager).unwrap();

        let mut app = test::init_service(
            App::new()
                .data(thread_pool.clone())
                .route("/api/user/create", web::post().to(user::create))
                .route("/api/auth/refresh_tokens", web::post().to(refresh_tokens)),
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

        let db_connection = thread_pool.get().unwrap();

        let create_user_res = test::call_service(
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
        .await;

        let user_tokens =
            actix_web::test::read_body_json::<jwt::TokenPair, _>(create_user_res).await;
        let user_id = jwt::read_claims(&user_tokens.access_token.to_string())
            .unwrap()
            .uid;

        let refresh_token_payload = RefreshToken(user_tokens.refresh_token.to_string() + "e");

        let req = test::TestRequest::post()
            .uri("/api/auth/refresh_tokens")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&refresh_token_payload).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);

        let refresh_token_payload = RefreshToken(user_tokens.refresh_token.to_string());

        let req = test::TestRequest::post()
            .uri("/api/auth/refresh_tokens")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&refresh_token_payload).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let token_pair = actix_web::test::read_body_json::<jwt::TokenPair, _>(res).await;

        let access_token = token_pair.access_token.to_string();
        let refresh_token = token_pair.refresh_token.to_string();

        assert!(access_token.len() > 0);
        assert!(refresh_token.len() > 0);

        assert!(jwt::is_on_blacklist(&refresh_token_payload.0, &db_connection).unwrap());
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
    async fn test_logout() {
        let manager = ConnectionManager::<PgConnection>::new(env::db::DATABASE_URL.as_str());
        let thread_pool = r2d2::Pool::builder().build(manager).unwrap();

        let mut app = test::init_service(
            App::new()
                .data(thread_pool.clone())
                .route("/api/user/create", web::post().to(user::create))
                .route("/api/auth/logout", web::post().to(logout)),
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

        let db_connection = thread_pool.get().unwrap();

        let create_user_res = test::call_service(
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
        .await;

        let user_tokens =
            actix_web::test::read_body_json::<jwt::TokenPair, _>(create_user_res).await;

        let logout_payload = RefreshToken(user_tokens.refresh_token.to_string());

        let req = test::TestRequest::post()
            .uri("/api/auth/logout")
            .header("content-type", "application/json")
            .set_payload(serde_json::ser::to_vec(&logout_payload).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        assert!(jwt::is_on_blacklist(&logout_payload.0, &db_connection).unwrap());
    }
}
