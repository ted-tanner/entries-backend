use entries_utils::token::{Token, TokenError};

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest};
use futures::future;
use std::marker::PhantomData;

use crate::middleware::{into_actix_error_res, TokenLocation};

pub struct SpecialAccessToken<T: for<'a> Token<'a>, L: TokenLocation>(
    pub T,
    PhantomData<T>,
    PhantomData<L>,
);

impl<T, L> FromRequest for SpecialAccessToken<T, L>
where
    T: for<'a> Token<'a>,
    L: TokenLocation,
{
    type Error = actix_web::error::Error;
    type Future = future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token = into_actix_error_res(match L::get_from_request(req, T::token_name()) {
            Some(t) => Ok(t),
            None => Err(TokenError::TokenMissing),
        });

        let token = match token {
            Ok(t) => t,
            Err(e) => return future::err(e),
        };

        let decoded_token = into_actix_error_res(match T::from_str(token) {
            Ok(t) => Ok(t),
            Err(_e) => Err(TokenError::TokenInvalid),
        });

        let decoded_token = match decoded_token {
            Ok(t) => t,
            Err(e) => return future::err(e),
        };

        future::ok(SpecialAccessToken(decoded_token, PhantomData, PhantomData))
    }
}
