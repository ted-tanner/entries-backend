pub mod app_version;
pub mod auth;
pub mod special_access_token;

mod limiter;

pub use limiter::Limiter;

use entries_common::token::TokenError;

use actix_web::HttpRequest;
use std::borrow::Cow;

use crate::handlers::error::HttpErrorResponse;

pub trait TokenLocation {
    fn get_from_request<'a>(req: &'a HttpRequest, key: &str) -> Option<&'a str>;
}

pub struct FromQuery {}
pub struct FromHeader {}

impl TokenLocation for FromQuery {
    fn get_from_request<'a>(req: &'a HttpRequest, key: &str) -> Option<&'a str> {
        let query_string = req.query_string();
        let pos = query_string.find(key)?;

        if query_string.len() < (pos + key.len() + 2) {
            return None;
        }

        let token_start = pos + key.len() + 1; // + 1 to account for equals sign (=)
        let token_end = match &query_string[token_start..].find('&') {
            Some(p) => token_start + p,
            None => query_string.len(),
        };

        Some(&query_string[token_start..token_end])
    }
}

impl TokenLocation for FromHeader {
    fn get_from_request<'a>(req: &'a HttpRequest, key: &str) -> Option<&'a str> {
        let header = req.headers().get(key)?;
        header.to_str().ok()
    }
}

#[inline(always)]
fn into_actix_error_res<T>(result: Result<T, TokenError>) -> Result<T, HttpErrorResponse> {
    match result {
        Ok(t) => Ok(t),
        Err(TokenError::TokenInvalid) => Err(HttpErrorResponse::IncorrectCredential(
            Cow::Borrowed("Token is invalid"),
        )),
        Err(TokenError::TokenExpired) => Err(HttpErrorResponse::TokenExpired(Cow::Borrowed(
            "Token is expired",
        ))),
        Err(TokenError::TokenMissing) => Err(HttpErrorResponse::TokenMissing(Cow::Borrowed(
            "Token is missing",
        ))),
        Err(TokenError::WrongTokenType) => Err(HttpErrorResponse::WrongTokenType(Cow::Borrowed(
            "Incorrect token type",
        ))),
    }
}
