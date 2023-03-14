use budgetapp_utils::auth_token;

use actix_web::dev::Payload;
use actix_web::{error, FromRequest, HttpRequest};
use futures::future;

use crate::env;

#[derive(Debug)]
pub struct AuthorizedUserClaims(pub auth_token::TokenClaims);

impl FromRequest for AuthorizedUserClaims {
    type Error = error::Error;
    type Future = future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        const INVALID_TOKEN_MSG: &str = "Token is invalid";

        let auth_header = match req.headers().get("Authorization") {
            Some(header) => header,
            None => return future::err(error::ErrorUnauthorized("No token provided")),
        };

        let mut header_parts_iter = match auth_header.to_str() {
            Ok(h) => h,
            Err(_) => return future::err(error::ErrorUnauthorized(INVALID_TOKEN_MSG)),
        }
        .split_ascii_whitespace();

        match header_parts_iter.next() {
            Some(str) => {
                if str.to_ascii_lowercase() != "bearer" {
                    return future::err(error::ErrorUnauthorized(INVALID_TOKEN_MSG));
                }
            }
            None => return future::err(error::ErrorUnauthorized(INVALID_TOKEN_MSG)),
        };

        let token = match header_parts_iter.next() {
            Some(str) => str,
            None => return future::err(error::ErrorUnauthorized(INVALID_TOKEN_MSG)),
        };

        let claims = match auth_token::validate_token(
            token,
            auth_token::TokenType::Access,
            &env::CONF.keys.token_signing_key,
            &env::CONF.keys.token_encryption_cipher,
        ) {
            Ok(c) => c,
            Err(_) => return future::err(error::ErrorUnauthorized(INVALID_TOKEN_MSG)),
        };

        future::ok(AuthorizedUserClaims(claims))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use budgetapp_utils::models::user::NewUser;

    use actix_web::test;
    use rand::prelude::*;
    use std::time::SystemTime;
    use uuid::Uuid;

    #[actix_rt::test]
    async fn test_auth_token_user_auth_middleware() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            email: &format!("test_user{}@test.com", &user_number),
            is_verified: true,
            created_timestamp: timestamp,
        };

        let token = auth_token::generate_token(
            &auth_token::TokenParams {
                user_id: new_user.id,
                user_email: new_user.email,
            },
            auth_token::TokenType::Access,
            env::CONF.lifetimes.access_token_lifetime,
            &env::CONF.keys.token_signing_key,
            &env::CONF.keys.token_encryption_cipher,
        )
        .unwrap();

        let req = test::TestRequest::get()
            .insert_header(("authorization", format!("Bearer {}", &token.to_string())))
            .to_http_request();

        let user_claims = AuthorizedUserClaims::from_request(&req, &mut Payload::None)
            .into_inner()
            .unwrap()
            .0;

        assert_eq!(user_claims.uid, user_id);

        let req = test::TestRequest::get()
            .insert_header(("authorization", format!("Bearer {}", &token.to_string())))
            .to_http_request();

        let user_claims = AuthorizedUserClaims::from_request(&req, &mut Payload::None)
            .into_inner()
            .unwrap()
            .0;

        assert_eq!(user_claims.uid, user_id);
    }

    #[actix_rt::test]
    async fn test_auth_middleware_rejects_request_without_auth_header() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            email: &format!("test_user{}@test.com", &user_number),
            is_verified: true,
            created_timestamp: timestamp,
        };

        let _token = auth_token::generate_token(
            &auth_token::TokenParams {
                user_id: new_user.id,
                user_email: new_user.email,
            },
            auth_token::TokenType::Access,
            env::CONF.lifetimes.access_token_lifetime,
            &env::CONF.keys.token_signing_key,
            &env::CONF.keys.token_encryption_cipher,
        )
        .unwrap();

        let req = test::TestRequest::get().to_http_request();
        let res = AuthorizedUserClaims::from_request(&req, &mut Payload::None).into_inner();

        assert!(res.is_err());
    }

    #[actix_rt::test]
    async fn test_auth_middleware_rejects_header_without_bearer_keyword() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            email: &format!("test_user{}@test.com", &user_number),
            is_verified: true,
            created_timestamp: timestamp,
        };

        let token = auth_token::generate_token(
            &auth_token::TokenParams {
                user_id: new_user.id,
                user_email: new_user.email,
            },
            auth_token::TokenType::Access,
            env::CONF.lifetimes.access_token_lifetime,
            &env::CONF.keys.token_signing_key,
            &env::CONF.keys.token_encryption_cipher,
        )
        .unwrap();

        let req = test::TestRequest::get()
            .insert_header(("authorization", token.to_string()))
            .to_http_request();

        let res = AuthorizedUserClaims::from_request(&req, &mut Payload::None).into_inner();

        assert!(res.is_err());
    }

    #[actix_rt::test]
    async fn test_auth_middleware_rejects_header_without_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            email: &format!("test_user{}@test.com", &user_number),
            is_verified: true,
            created_timestamp: timestamp,
        };

        let _token = auth_token::generate_token(
            &auth_token::TokenParams {
                user_id: new_user.id,
                user_email: new_user.email,
            },
            auth_token::TokenType::Access,
            env::CONF.lifetimes.access_token_lifetime,
            &env::CONF.keys.token_signing_key,
            &env::CONF.keys.token_encryption_cipher,
        )
        .unwrap();

        let req = test::TestRequest::get()
            .insert_header(("authorization", "bearer"))
            .to_http_request();
        let res = AuthorizedUserClaims::from_request(&req, &mut Payload::None).into_inner();

        assert!(res.is_err());
    }

    #[actix_rt::test]
    async fn test_auth_middleware_rejects_invalid_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            email: &format!("test_user{}@test.com", &user_number),
            is_verified: true,
            created_timestamp: timestamp,
        };

        let token = auth_token::generate_token(
            &auth_token::TokenParams {
                user_id: new_user.id,
                user_email: new_user.email,
            },
            auth_token::TokenType::Access,
            env::CONF.lifetimes.access_token_lifetime,
            &env::CONF.keys.token_signing_key,
            &env::CONF.keys.token_encryption_cipher,
        )
        .unwrap()
        .to_string();

        // Remove the last char of the token
        let broken_token = &token[0..token.len() - 1];

        let req = test::TestRequest::get()
            .insert_header(("authorization", format!("Bearer {broken_token}")))
            .to_http_request();

        let res = AuthorizedUserClaims::from_request(&req, &mut Payload::None).into_inner();

        assert!(res.is_err());
    }

    #[actix_rt::test]
    async fn test_auth_middleware_rejects_refresh_token_in_auth_header() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            email: &format!("test_user{}@test.com", &user_number),
            is_verified: true,
            created_timestamp: timestamp,
        };

        let token = auth_token::generate_token(
            &auth_token::TokenParams {
                user_id: new_user.id,
                user_email: new_user.email,
            },
            auth_token::TokenType::Refresh,
            env::CONF.lifetimes.access_token_lifetime,
            &env::CONF.keys.token_signing_key,
            &env::CONF.keys.token_encryption_cipher,
        )
        .unwrap();

        let req = test::TestRequest::get()
            .insert_header(("authorization", format!("Bearer {}", &token.to_string())))
            .to_http_request();

        let res = AuthorizedUserClaims::from_request(&req, &mut Payload::None).into_inner();

        assert!(res.is_err());
    }
}
