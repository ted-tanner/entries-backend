use std::str::FromStr;

use actix_web::{web, HttpResponse};
use log::error;

use crate::db_utils;
use crate::definitions::ThreadPool;
use crate::handlers::request_io::CredentialPair;
use crate::handlers::request_io::RefreshToken;
use crate::utils::jwt;
use crate::utils::password_hasher;

pub async fn sign_in(
    thread_pool: web::Data<ThreadPool>,
    credentials: web::Json<CredentialPair>,
) -> Result<HttpResponse, actix_web::Error> {
    const INVALID_CREDENTIALS_MSG: &str = "Incorrect email or password";

    if !credentials.validate_email_address() {
        return Ok(HttpResponse::BadRequest().body("Invalid email address"));
    }

    let password = credentials.password.clone();

    Ok(web::block(move || {
        let db_connection = thread_pool.get().expect("Failed to access thread pool");
        db_utils::user::get_user_by_email(&db_connection, &credentials.email)
    })
    .await
    .map(
        |user| match password_hasher::verify_hash(&password, &user.password_hash) {
            true => {
                let token_pair = jwt::generate_token_pair(user.id);

                let token_pair = match token_pair {
                    Ok(token_pair) => token_pair,
                    Err(e) => {
                        error!("{}", e);
                        return HttpResponse::InternalServerError()
                            .body("Failed to generate tokens for new user. User has been created");
                    }
                };

                HttpResponse::Ok().json(token_pair)
            }
            false => return HttpResponse::Unauthorized().body(INVALID_CREDENTIALS_MSG),
        },
    )
    .map_err(|_| {
        // Hash the provided password and generate a token pair unnecessarily so attackers
        // can't tell the difference between an incorrect password and a non-existent email

        let password = if password.len() == 0 { " " } else { &password };

        password_hasher::hash_argon2id(password);
        jwt::generate_token_pair(
            uuid::Uuid::from_str("00000000-0000-0000-0000-000000000000")
                .expect("Failed to parse an all-zero UUID"),
        )
        .unwrap_or(jwt::TokenPair::empty());

        HttpResponse::Unauthorized().body(INVALID_CREDENTIALS_MSG)
    })?)
}

pub async fn refresh_tokens(
    thread_pool: web::Data<ThreadPool>,
    token: web::Json<RefreshToken>,
) -> Result<HttpResponse, actix_web::Error> {
    let refresh_token = &token.0 .0.clone();
    let db_connection = &thread_pool.get().expect("Failed to access thread pool");

    Ok(web::block(move || {
        jwt::validate_refresh_token(
            token.0 .0.as_str(),
            &thread_pool.get().expect("Failed to access thread pool"),
        )
    })
    .await
    .map(|user_id| {
        match jwt::blacklist_token(refresh_token.as_str(), db_connection) {
            Ok(_) => {}
            Err(e) => error!("Failed to blacklist token: {}", e),
        }

        let token_pair = jwt::generate_token_pair(user_id);

        let token_pair = match token_pair {
            Ok(token_pair) => token_pair,
            Err(e) => {
                error!("Failed to generate tokens for new user: {}", e);
                return HttpResponse::InternalServerError()
                    .body("Failed to generate tokens for new user");
            }
        };

        HttpResponse::Ok().json(token_pair)
    })
    .map_err(|e| match e {
        actix_web::error::BlockingError::Error(err) => match err.kind() {
            jwt::ErrorKind::TokenInvalid => HttpResponse::Unauthorized().body("Token is invalid"),
            jwt::ErrorKind::TokenBlacklisted => {
                HttpResponse::Unauthorized().body("Token has been blacklisted")
            }
            jwt::ErrorKind::TokenExpired => HttpResponse::Unauthorized().body("Token has expired"),
            jwt::ErrorKind::WrongTokenType => {
                HttpResponse::Unauthorized().body("Incorrect token type")
            }
            _ => HttpResponse::InternalServerError().body("Error generating new tokens"),
        },
        actix_web::error::BlockingError::Canceled => {
            HttpResponse::InternalServerError().body("Response canceled")
        }
    })?)
}

pub async fn logout(
    thread_pool: web::Data<ThreadPool>,
    refresh_token: web::Json<RefreshToken>,
) -> Result<HttpResponse, actix_web::Error> {
    Ok(match web::block(move || {
        jwt::blacklist_token(
            refresh_token.0 .0.as_str(),
            &thread_pool.get().expect("Failed to access thread pool"),
        )
    })
    .await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(_) => {
            error!("Failed to blacklist token");
            HttpResponse::InternalServerError().body("Failed to blacklist token")
        },
    })
}
