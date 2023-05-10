use budgetapp_utils::token::auth_token::{AuthToken, AuthTokenClaims, AuthTokenType};
use budgetapp_utils::token::{Token, TokenError};

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest};
use futures::future;
use std::marker::PhantomData;
use std::mem;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::env;
use crate::middleware::{into_actix_error_res, TokenLocation};

pub trait RequestAuthTokenType {
    fn token_name() -> &'static str;
    fn token_type() -> AuthTokenType;
    fn token_lifetime() -> Duration;
}

pub struct Access {}
pub struct Refresh {}
pub struct SignIn {}
pub struct UserCreation {}
pub struct UserDeletion {}

impl RequestAuthTokenType for Access {
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

impl RequestAuthTokenType for Refresh {
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

impl RequestAuthTokenType for SignIn {
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

impl RequestAuthTokenType for UserCreation {
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

impl RequestAuthTokenType for UserDeletion {
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

pub struct UnverifiedToken<T: RequestAuthTokenType, L: TokenLocation>(
    pub AuthToken,
    PhantomData<T>,
    PhantomData<L>,
)
where
    T: RequestAuthTokenType,
    L: TokenLocation;

impl<T, L> UnverifiedToken<T, L>
where
    T: RequestAuthTokenType,
    L: TokenLocation,
{
    pub fn verify(self) -> Result<AuthTokenClaims, TokenError> {
        verify_token(self.0, T::token_type())
    }
}

impl<T, L> FromRequest for UnverifiedToken<T, L>
where
    T: RequestAuthTokenType,
    L: TokenLocation,
{
    type Error = actix_web::Error;
    type Future = future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        match into_actix_error_res(get_and_decode_token::<T, L>(req)) {
            Ok(c) => future::ok(UnverifiedToken(c, PhantomData, PhantomData)),
            Err(e) => future::err(e),
        }
    }
}

#[derive(Debug)]
pub struct VerifiedToken<T: RequestAuthTokenType, L: TokenLocation>(
    pub AuthTokenClaims,
    PhantomData<T>,
    PhantomData<L>,
)
where
    T: RequestAuthTokenType,
    L: TokenLocation;

impl<T, L> FromRequest for VerifiedToken<T, L>
where
    T: RequestAuthTokenType,
    L: TokenLocation,
{
    type Error = actix_web::Error;
    type Future = future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let decoded_token = match into_actix_error_res(get_and_decode_token::<T, L>(req)) {
            Ok(t) => t,
            Err(e) => return future::err(e),
        };

        let claims = match into_actix_error_res(verify_token(decoded_token, T::token_type())) {
            Ok(c) => c,
            Err(e) => return future::err(e),
        };

        future::ok(VerifiedToken(claims, PhantomData, PhantomData))
    }
}

#[inline]
fn get_and_decode_token<T, L>(req: &HttpRequest) -> Result<AuthToken, TokenError>
where
    T: RequestAuthTokenType,
    L: TokenLocation,
{
    let token = match L::get_from_request(req, T::token_name()) {
        Some(h) => h,
        None => return Err(TokenError::TokenMissing),
    };

    AuthToken::from_str(token)
}

#[inline]
fn verify_token(
    mut decoded_token: AuthToken,
    expected_type: AuthTokenType,
) -> Result<AuthTokenClaims, TokenError> {
    if !decoded_token.verify(&env::CONF.keys.token_signing_key) {
        return Err(TokenError::TokenInvalid);
    }

    if decoded_token
        .decrypt(&env::CONF.keys.token_encryption_cipher)
        .is_err()
    {
        return Err(TokenError::TokenInvalid);
    }

    let claims = decoded_token.claims();

    if mem::discriminant(&claims.token_type) != mem::discriminant(&expected_type) {
        return Err(TokenError::WrongTokenType);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Failed to fetch system time")
        .as_secs();

    if claims.expiration <= now {
        return Err(TokenError::TokenExpired);
    }

    Ok(claims)
}
