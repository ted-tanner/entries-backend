use actix_web::{error, FromRequest};
use futures::future;

use crate::utils::jwt;

#[derive(Debug)]
pub struct AuthorizedUserId(pub uuid::Uuid);

impl FromRequest for AuthorizedUserId {
    type Error = actix_web::Error;
    type Future = future::Ready<Result<Self, Self::Error>>;
    type Config = ();

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        const INVALID_TOKEN_MSG: &'static str = "Token is invalid";

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

        let user_id = match jwt::validate_access_token(token) {
            Ok(claims) => claims.uid,
            _ => return future::err(error::ErrorUnauthorized(INVALID_TOKEN_MSG)),
        };

        future::ok(AuthorizedUserId(user_id))
    }
}
