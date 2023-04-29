pub mod app_version;
pub mod auth;
pub mod special_access_token;

use budgetapp_utils::token::TokenError;

use actix_web::error::ErrorUnauthorized;
use actix_web::HttpRequest;

pub trait TokenLocation {
    fn get_from_request<'a>(req: &'a HttpRequest, key: &str) -> Option<&'a str>;
}

pub struct FromQuery {}
pub struct FromHeader {}

impl TokenLocation for FromQuery {
    fn get_from_request<'a>(req: &'a HttpRequest, key: &str) -> Option<&'a str> {
        let query_string = req.query_string();
        let pos = match query_string.find(key) {
            Some(p) => p,
            None => return None,
        };

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
        let header = match req.headers().get(key) {
            Some(header) => header,
            None => return None,
        };

        match header.to_str() {
            Ok(h) => return Some(h),
            Err(_) => return None,
        }
    }
}

#[inline(always)]
fn into_actix_error_res<T>(result: Result<T, TokenError>) -> Result<T, actix_web::Error> {
    match result {
        Ok(t) => Ok(t),
        Err(TokenError::TokenInvalid) => Err(ErrorUnauthorized("Token is invalid")),
        Err(TokenError::TokenExpired) => Err(ErrorUnauthorized("Token is expired")),
        Err(TokenError::TokenMissing) => Err(ErrorUnauthorized("Token is missing")),
        Err(TokenError::WrongTokenType) => Err(ErrorUnauthorized("Incorrect token type")),
    }
}
