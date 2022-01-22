use actix_web::dev::Payload;
use actix_web::{error, FromRequest, HttpRequest};
use futures::future;

use crate::utils::jwt;

#[derive(Debug)]
pub struct AuthorizedUserClaims(pub jwt::TokenClaims);

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

        let claims = match jwt::validate_access_token(token) {
            Ok(c) => c,
            Err(_) => return future::err(error::ErrorUnauthorized(INVALID_TOKEN_MSG)),
        };

        future::ok(AuthorizedUserClaims(claims))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::test;
    use chrono::NaiveDate;
    use rand::prelude::*;
    use uuid::Uuid;

    use crate::models::user::NewUser;

    #[test]
    async fn test_jwt_user_auth_middleware() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let token = jwt::generate_access_token(jwt::JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        let req = test::TestRequest::get()
            .insert_header(("authorization", format!("Bearer {}", &token.to_string())))
            .to_http_request();

        let user_claims = AuthorizedUserClaims::from_request(&req, &mut Payload::None)
            .into_inner()
            .unwrap()
            .0;

        assert_eq!(&user_claims.uid, &user_id);

        let req = test::TestRequest::get()
            .insert_header(("authorization", format!("Bearer {}", &token.to_string())))
            .to_http_request();

        let user_claims = AuthorizedUserClaims::from_request(&req, &mut Payload::None)
            .into_inner()
            .unwrap()
            .0;

        assert_eq!(&user_claims.uid, &user_id);
    }

    #[test]
    async fn test_auth_middleware_rejects_request_without_auth_header() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let _token = jwt::generate_access_token(jwt::JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        let req = test::TestRequest::get().to_http_request();

        let res = AuthorizedUserClaims::from_request(&req, &mut Payload::None).into_inner();

        assert!(res.is_err());
    }

    #[test]
    async fn test_auth_middleware_rejects_header_without_bearer_keyword() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let token = jwt::generate_access_token(jwt::JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        let req = test::TestRequest::get()
            .insert_header(("authorization", (&token.to_string()).to_string()))
            .to_http_request();

        let res = AuthorizedUserClaims::from_request(&req, &mut Payload::None).into_inner();

        assert!(res.is_err());
    }

    #[test]
    async fn test_auth_middleware_rejects_header_without_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let _ = jwt::generate_access_token(jwt::JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        let req = test::TestRequest::get()
            .insert_header(("authorization", "bearer"))
            .to_http_request();
        let res = AuthorizedUserClaims::from_request(&req, &mut Payload::None).into_inner();

        assert!(res.is_err());
    }

    #[test]
    async fn test_auth_middleware_rejects_invalid_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let token = jwt::generate_access_token(jwt::JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap()
        .to_string();

        // Remove the last char of the token
        let broken_token = &token[0..token.len() - 1];

        let req = test::TestRequest::get()
            .insert_header(("authorization", format!("Bearer {}", broken_token)))
            .to_http_request();

        let res = AuthorizedUserClaims::from_request(&req, &mut Payload::None).into_inner();

        assert!(res.is_err());
    }

    #[test]
    async fn test_auth_middleware_rejects_refresh_token_in_auth_header() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let token = jwt::generate_refresh_token(jwt::JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        let req = test::TestRequest::get()
            .insert_header(("authorization", format!("Bearer {}", &token.to_string())))
            .to_http_request();

        let res = AuthorizedUserClaims::from_request(&req, &mut Payload::None).into_inner();

        assert!(res.is_err());
    }
}
