use budgetapp_utils::token::{TokenError, UserToken};
use budgetapp_utils::token::auth_token::{AuthToken, AuthTokenClaims, AuthTokenType};

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest};
use actix_web::error::ErrorUnauthorized;
use futures::future;

use crate::env;

#[derive(Debug)]
pub struct AuthorizedUserClaims(pub AuthTokenClaims);

impl FromRequest for AuthorizedUserClaims {
    type Error = actix_web::error::Error;
    type Future = future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        const INVALID_TOKEN_MSG: &str = "Token is invalid";

        let auth_header = match req.headers().get("Authorization") {
            Some(header) => header,
            None => return future::err(ErrorUnauthorized("No token provided")),
        };

        let mut header_parts_iter = match auth_header.to_str() {
            Ok(h) => h,
            Err(_) => return future::err(ErrorUnauthorized(INVALID_TOKEN_MSG)),
        }
        .split_ascii_whitespace();

        match header_parts_iter.next() {
            Some(h) => {
                if !h.eq_ignore_ascii_case("bearer") {
                    return future::err(error::ErrorUnauthorized(INVALID_TOKEN_MSG));
                }
            }
            None => return future::err(error::ErrorUnauthorized(INVALID_TOKEN_MSG)),
        };

        let token = match header_parts_iter.next() {
            Some(t) => t,
            None => return future::err(error::ErrorUnauthorized(INVALID_TOKEN_MSG)),
        };

        let mut decoded_token = match AuthToken::from_str(token) {
            Ok(t) => t,
            Err(_) => return future::err(ErrorUnauthorized(INVALID_TOKEN_MSG)),
        };

        if !decoded_token.verify(&env::CONF.keys.token_signing_key) {
            return future::err(ErrorUnauthorized(INVALID_TOKEN_MSG));
        }

        if let Err(_) = decoded_token.decrypt(&env::CONF.keys.token_encryption_cipher) {
            return future::err(ErrorUnauthorized(INVALID_TOKEN_MSG));
        }

        let claims = decoded_token.claims();

        if !matches!(claims.token_type, AuthTokenClaims::Access) {
            return future::err(ErrorUnauthorized(INVALID_TOKEN_MSG));
        }

        future::ok(AuthorizedUserClaims(claims))
    }
}
