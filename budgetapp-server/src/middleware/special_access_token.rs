use budgetapp_utils::token::{Token, TokenError};

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
        let token = match L::get_from_request(req, T::token_name()) {
            Some(t) => t,
            None => return into_actix_error_res(TokenError::TokenMissing),
        };

        let decoded_token = match T::from_str(&token) {
            Ok(t) => t,
            Err(e) => return into_actix_error_res(TokenError::TokenMissing),
        };

        future::ok(SpecialAccessToken(decoded_token, PhantomData, PhantomData))
    }
}
