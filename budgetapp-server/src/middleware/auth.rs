use budgetapp_utils::token::auth_token::{AuthToken, AuthTokenClaims, AuthTokenType};
use budgetapp_utils::token::UserToken;

use actix_web::dev::Payload;
use actix_web::error::ErrorUnauthorized;
use actix_web::{FromRequest, HttpRequest};
use futures::future;
use std::marker::PhantomData;
use std::mem;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::env;

pub trait TokenLocation<'a> {
    fn get_from_request(req: &'a HttpRequest, key: &str) -> Option<&'a str>;
}

pub struct FromQuery {}
pub struct FromHeader {}

impl<'a> TokenLocation<'a> for FromQuery {
    fn get_from_request(req: &'a HttpRequest, key: &str) -> Option<&'a str> {
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

impl<'a> TokenLocation<'a> for FromHeader {
    fn get_from_request(req: &'a HttpRequest, key: &str) -> Option<&'a str> {
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


pub trait RequestTokenType {
    fn token_name() -> &'static str;
    fn token_type() -> AuthTokenType;
    fn token_lifetime() -> Duration;
}

pub struct AccessToken {}
pub struct RefreshToken {}
pub struct SignInToken {}
pub struct UserCreationToken {}
pub struct UserDeletionToken {}

impl RequestTokenType for AccessToken {
    fn token_name() -> &'static str { "AccessToken" }
    fn token_type() -> AuthTokenType { AuthTokenType::Access }
    fn token_lifetime() -> Duration { env::CONF.lifetimes.access_token_lifetime }
}

impl RequestTokenType for RefreshToken {
    fn token_name() -> &'static str { "RefreshToken" }
    fn token_type() -> AuthTokenType { AuthTokenType::Refresh }
    fn token_lifetime() -> Duration { env::CONF.lifetimes.refresh_token_lifetime }
}

impl RequestTokenType for SignInToken {
    fn token_name() -> &'static str { "SignInToken" }
    fn token_type() -> AuthTokenType { AuthTokenType::SignIn }
    fn token_lifetime() -> Duration { env::CONF.lifetimes.signin_token_lifetime }
}

impl RequestTokenType for UserCreationToken {
    fn token_name() -> &'static str { "UserCreation" }
    fn token_type() -> AuthTokenType { AuthTokenType::UserCreation }
    fn token_lifetime() -> Duration { env::CONF.lifetimes.user_creation_token_lifetime }
}

impl RequestTokenType for UserDeletionToken {
    fn token_name() -> &'static str { "UserDeletion" }
    fn token_type() -> AuthTokenType { AuthTokenType::UserDeletion }
    fn token_lifetime() -> Duration { env::CONF.lifetimes.user_deletion_token_lifetime }
}


pub trait TokenExpirationValidator {
    fn is_expired(expiration: u64, token_lifetime: Duration) -> bool;
}

pub struct ValidateExpiration {}
pub struct IgnoreExpiration {}

impl TokenExpirationValidator for ValidateExpiration {
    #[inline(always)]
    fn is_expired(expiration: u64, token_lifetime: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_secs();

        expiration <= now
    }
}

impl TokenExpirationValidator for IgnoreExpiration {
    #[inline(always)]
    fn is_expired(expiration: u64, token_lifetime: Duration) -> bool {
        false
    }
}


#[derive(Debug)]
pub struct VerifiedTokenClaims<'a, T, L, E>(
    pub AuthTokenClaims,
    PhantomData<T>,
    PhantomData<&'a L>,
    PhantomData<E>,
)
where
    T: RequestTokenType,
    L: TokenLocation<'a>,
    E: TokenExpirationValidator;


impl<'a, T, L, E> FromRequest for VerifiedTokenClaims<'a, T, L, E>
where
    T: RequestTokenType,
    L: TokenLocation<'a>,
    E: TokenExpirationValidator,
{
    type Error = actix_web::error::Error;
    type Future = future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token = match L::get_from_request(req, T::token_name()) {
            Some(h) => h,
            None => return future::err(ErrorUnauthorized("Token missing or invalid")),
        };

        let mut decoded_token = match AuthToken::from_str(token) {
            Ok(t) => t,
            Err(_) => return future::err(ErrorUnauthorized("Invalid token")),
        };

        if !decoded_token.verify(&env::CONF.keys.token_signing_key) {
            return future::err(ErrorUnauthorized("Invalid tokenx"));
        }

        if let Err(_) = decoded_token.decrypt(&env::CONF.keys.token_encryption_cipher) {
            return future::err(ErrorUnauthorized("Could not decrypt token"));
        }

        let claims = decoded_token.claims();

        if mem::discriminant(&claims.token_type) != mem::discriminant(&T::token_type()) {
            return future::err(ErrorUnauthorized("Incorrect token type"));
        }

        if E::is_expired(claims.expiration, T::token_lifetime()) {
            return future::err(ErrorUnauthorized("Token expired"));
        }

        future::ok(VerifiedTokenClaims(claims, PhantomData, PhantomData, PhantomData))
    }
}
