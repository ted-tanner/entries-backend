pub mod app_version;
pub mod auth;
pub mod client_type;
pub mod special_access_token;

pub mod rate_limiting;

pub use rate_limiting::{
    CircuitBreaker as CircuitBreakerStrategy, FairUse as FairUseStrategy, RateLimiter,
};

use entries_common::token::TokenError;

use actix_web::HttpRequest;
use std::borrow::Cow;

use crate::handlers::error::HttpErrorResponse;

pub struct ExtractedToken<'a> {
    pub value: Cow<'a, str>,
    pub from_cookie: bool,
}

pub trait TokenLocation {
    fn get_from_request<'a>(req: &'a HttpRequest, key: &str) -> Option<ExtractedToken<'a>>;
}

pub struct FromQuery {}
pub struct FromHeaderOrCookie {}

impl TokenLocation for FromQuery {
    fn get_from_request<'a>(req: &'a HttpRequest, key: &str) -> Option<ExtractedToken<'a>> {
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

        Some(ExtractedToken {
            value: Cow::Borrowed(&query_string[token_start..token_end]),
            from_cookie: false,
        })
    }
}

impl TokenLocation for FromHeaderOrCookie {
    fn get_from_request<'a>(req: &'a HttpRequest, key: &str) -> Option<ExtractedToken<'a>> {
        if let Some(header) = req.headers().get(key) {
            if let Ok(s) = header.to_str() {
                return Some(ExtractedToken {
                    value: Cow::Borrowed(s),
                    from_cookie: false,
                });
            }
        }

        req.cookie(key).map(|c| ExtractedToken {
            value: Cow::Owned(c.value().to_string()),
            from_cookie: true,
        })
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
