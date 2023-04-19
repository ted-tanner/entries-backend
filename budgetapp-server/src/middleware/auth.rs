use budgetapp_utils::token::auth_token::{AuthToken, AuthTokenClaims, AuthTokenType};
use budgetapp_utils::token::{TokenError, UserToken};

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest};
use futures::future;
use std::marker::PhantomData;
use std::mem;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::env;

trait TokenLocation {
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

trait RequestTokenType {
    fn token_name() -> &'static str;
    fn token_type() -> AuthTokenType;
    fn token_lifetime() -> Duration;
}

pub struct Access {}
pub struct Refresh {}
pub struct SignIn {}
pub struct UserCreation {}
pub struct UserDeletion {}

impl RequestTokenType for Access {
    fn token_name() -> &'static str {
        "AccessToken"
    }
    fn token_type() -> AuthTokenType {
        AuthTokenType::Access
    }
    fn token_lifetime() -> Duration {
        env::CONF.lifetimes.access_token_lifetime
    }
}

impl RequestTokenType for Refresh {
    fn token_name() -> &'static str {
        "RefreshToken"
    }
    fn token_type() -> AuthTokenType {
        AuthTokenType::Refresh
    }
    fn token_lifetime() -> Duration {
        env::CONF.lifetimes.refresh_token_lifetime
    }
}

impl RequestTokenType for SignIn {
    fn token_name() -> &'static str {
        "SignInToken"
    }
    fn token_type() -> AuthTokenType {
        AuthTokenType::SignIn
    }
    fn token_lifetime() -> Duration {
        env::CONF.lifetimes.signin_token_lifetime
    }
}

impl RequestTokenType for UserCreation {
    fn token_name() -> &'static str {
        "UserCreationToken"
    }
    fn token_type() -> AuthTokenType {
        AuthTokenType::UserCreation
    }
    fn token_lifetime() -> Duration {
        env::CONF.lifetimes.user_creation_token_lifetime
    }
}

impl RequestTokenType for UserDeletion {
    fn token_name() -> &'static str {
        "UserDeletionToken"
    }
    fn token_type() -> AuthTokenType {
        AuthTokenType::UserDeletion
    }
    fn token_lifetime() -> Duration {
        env::CONF.lifetimes.user_deletion_token_lifetime
    }
}

#[derive(Debug)]
pub struct VerifiedToken<T, L>(
    pub Result<AuthTokenClaims, TokenError>,
    PhantomData<T>,
    PhantomData<L>,
)
where
    T: RequestTokenType,
    L: TokenLocation;

impl<T, L> FromRequest for VerifiedToken<T, L>
where
    T: RequestTokenType,
    L: TokenLocation,
{
    type Error = actix_web::error::Error;
    type Future = future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token = match L::get_from_request(req, T::token_name()) {
            Some(h) => h,
            None => {
                return future::ok(VerifiedToken(
                    Err(TokenError::TokenMissing),
                    PhantomData,
                    PhantomData,
                ))
            }
        };

        let mut decoded_token = match AuthToken::from_str(token) {
            Ok(t) => t,
            Err(_) => {
                return future::ok(VerifiedToken(
                    Err(TokenError::TokenInvalid),
                    PhantomData,
                    PhantomData,
                ))
            }
        };

        if !decoded_token.verify(&env::CONF.keys.token_signing_key) {
            return future::ok(VerifiedToken(
                Err(TokenError::TokenInvalid),
                PhantomData,
                PhantomData,
            ));
        }

        if let Err(_) = decoded_token.decrypt(&env::CONF.keys.token_encryption_cipher) {
            return future::ok(VerifiedToken(
                Err(TokenError::TokenInvalid),
                PhantomData,
                PhantomData,
            ));
        }

        let claims = decoded_token.claims();

        if mem::discriminant(&claims.token_type) != mem::discriminant(&T::token_type()) {
            return future::ok(VerifiedToken(
                Err(TokenError::WrongTokenType),
                PhantomData,
                PhantomData,
            ));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_secs();

        if expiration <= now {
            return future::ok(VerifiedToken(
                Err(TokenError::TokenExpired),
                PhantomData,
                PhantomData,
            ));
        }

        future::ok(VerifiedToken(Ok(claims), PhantomData, PhantomData))
    }
}
