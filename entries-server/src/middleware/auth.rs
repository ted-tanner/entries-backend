use entries_utils::token::auth_token::{AuthToken, AuthTokenClaims, AuthTokenType};
use entries_utils::token::{DecodedToken, Token, TokenError};

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest};
use futures::future;
use std::marker::PhantomData;
use std::mem;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::env;
use crate::handlers::error::HttpErrorResponse;
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
        env::CONF.access_token_lifetime
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
        env::CONF.refresh_token_lifetime
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
        env::CONF.signin_token_lifetime
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
        env::CONF.user_creation_token_lifetime
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
        env::CONF.user_deletion_token_lifetime
    }
}

type AuthDecodedToken = DecodedToken<<AuthToken as Token>::Claims, <AuthToken as Token>::Verifier>;

pub struct UnverifiedToken<T: RequestAuthTokenType, L: TokenLocation>(
    pub AuthDecodedToken,
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
    pub fn verify(&self) -> Result<AuthTokenClaims, TokenError> {
        verify_token(&self.0, T::token_type())
    }
}

impl<T, L> FromRequest for UnverifiedToken<T, L>
where
    T: RequestAuthTokenType,
    L: TokenLocation,
{
    type Error = HttpErrorResponse;
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
    type Error = HttpErrorResponse;
    type Future = future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let decoded_token = match into_actix_error_res(get_and_decode_token::<T, L>(req)) {
            Ok(t) => t,
            Err(e) => return future::err(e),
        };

        let claims = match into_actix_error_res(verify_token(&decoded_token, T::token_type())) {
            Ok(c) => c,
            Err(e) => return future::err(e),
        };

        future::ok(VerifiedToken(claims, PhantomData, PhantomData))
    }
}

#[inline]
fn get_and_decode_token<T, L>(req: &HttpRequest) -> Result<AuthDecodedToken, TokenError>
where
    T: RequestAuthTokenType,
    L: TokenLocation,
{
    let token = match L::get_from_request(req, T::token_name()) {
        Some(h) => h,
        None => return Err(TokenError::TokenMissing),
    };

    AuthToken::decode(token)
}

#[inline]
fn verify_token(
    decoded_token: &AuthDecodedToken,
    expected_type: AuthTokenType,
) -> Result<AuthTokenClaims, TokenError> {
    let claims = decoded_token.verify(&env::CONF.token_signing_key)?;
    let claims = claims.decrypt(&env::CONF.token_encryption_cipher)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::dev::Payload;
    use actix_web::test::TestRequest;
    use uuid::Uuid;

    use entries_utils::token::auth_token::{AuthToken, NewAuthTokenClaims};

    use crate::middleware::{FromHeader, FromQuery};

    #[actix_web::test]
    async fn test_verified_from_header() {
        let user_id = Uuid::new_v4();
        let user_email = "test1234@example.com";
        let exp = SystemTime::now() + Duration::from_secs(10);

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email: &user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(
            token_claims.encrypt(&env::CONF.token_encryption_cipher),
            &env::CONF.token_signing_key,
        );

        let req = TestRequest::default()
            .insert_header(("AccessToken", token.as_str()))
            .to_http_request();

        assert!(
            VerifiedToken::<Access, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .is_ok()
        );
        assert!(
            VerifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );
        assert!(
            VerifiedToken::<Refresh, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );
        assert!(
            VerifiedToken::<UserDeletion, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email: &user_email,
            expiration: exp,
            token_type: AuthTokenType::Refresh,
        };

        let token = AuthToken::sign_new(
            token_claims.encrypt(&env::CONF.token_encryption_cipher),
            &env::CONF.token_signing_key,
        );

        let req = TestRequest::default()
            .insert_header(("AccessToken", token.as_str()))
            .to_http_request();

        assert!(
            VerifiedToken::<Access, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );

        let req = TestRequest::default()
            .insert_header(("RefreshToken", token.as_str()))
            .to_http_request();

        assert!(
            VerifiedToken::<Access, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );

        let exp = SystemTime::now() - Duration::from_secs(10);

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email: &user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(
            token_claims.encrypt(&env::CONF.token_encryption_cipher),
            &env::CONF.token_signing_key,
        );

        let req = TestRequest::default()
            .insert_header(("AccessToken", token.as_str()))
            .to_http_request();

        assert!(
            VerifiedToken::<Access, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );

        let req = TestRequest::default().to_http_request();

        assert!(
            VerifiedToken::<Access, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );
    }

    #[actix_web::test]
    async fn test_verified_from_query() {
        let user_id = Uuid::new_v4();
        let user_email = "test1234@example.com";
        let exp = SystemTime::now() + Duration::from_secs(10);

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email: &user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(
            token_claims.encrypt(&env::CONF.token_encryption_cipher),
            &env::CONF.token_signing_key,
        );

        let req = TestRequest::default()
            .uri(&format!("/test?AccessToken={}", &token))
            .to_http_request();

        assert!(
            VerifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_ok()
        );
        assert!(
            VerifiedToken::<Access, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );
        assert!(
            VerifiedToken::<Refresh, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );
        assert!(
            VerifiedToken::<UserDeletion, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email: &user_email,
            expiration: exp,
            token_type: AuthTokenType::Refresh,
        };

        let token = AuthToken::sign_new(
            token_claims.encrypt(&env::CONF.token_encryption_cipher),
            &env::CONF.token_signing_key,
        );

        let req = TestRequest::default()
            .uri(&format!("/test?AccessToken={}", &token))
            .to_http_request();

        assert!(
            VerifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );

        let req = TestRequest::default()
            .uri(&format!("/test?RefreshToken={}", &token))
            .to_http_request();

        assert!(
            VerifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );

        let exp = SystemTime::now() - Duration::from_secs(10);

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email: &user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(
            token_claims.encrypt(&env::CONF.token_encryption_cipher),
            &env::CONF.token_signing_key,
        );

        let req = TestRequest::default()
            .uri(&format!("/test?AccessToken={}", &token))
            .to_http_request();

        assert!(
            VerifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );

        let req = TestRequest::default().to_http_request();

        assert!(
            VerifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );
    }

    #[actix_web::test]
    async fn test_unverified_from_header() {
        let user_id = Uuid::new_v4();
        let user_email = "test1234@example.com";
        let exp = SystemTime::now() + Duration::from_secs(10);

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email: &user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(
            token_claims.encrypt(&env::CONF.token_encryption_cipher),
            &env::CONF.token_signing_key,
        );

        let req = TestRequest::default()
            .insert_header(("AccessToken", token.as_str()))
            .to_http_request();

        assert!(
            UnverifiedToken::<Access, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .is_ok()
        );
        assert!(
            UnverifiedToken::<Access, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .unwrap()
                .verify()
                .is_ok()
        );
        assert!(
            UnverifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );
        assert!(
            UnverifiedToken::<Refresh, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );
        assert!(UnverifiedToken::<UserDeletion, FromHeader>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_err());

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email: &user_email,
            expiration: exp,
            token_type: AuthTokenType::Refresh,
        };

        let token = AuthToken::sign_new(
            token_claims.encrypt(&env::CONF.token_encryption_cipher),
            &env::CONF.token_signing_key,
        );

        let req = TestRequest::default()
            .insert_header(("AccessToken", token.as_str()))
            .to_http_request();

        assert!(
            UnverifiedToken::<Access, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .is_ok()
        );
        assert!(
            UnverifiedToken::<Access, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .unwrap()
                .verify()
                .is_err()
        );

        let req = TestRequest::default()
            .insert_header(("RefreshToken", token.as_str()))
            .to_http_request();

        assert!(
            UnverifiedToken::<Access, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );

        let exp = SystemTime::now() - Duration::from_secs(10);

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email: &user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(
            token_claims.encrypt(&env::CONF.token_encryption_cipher),
            &env::CONF.token_signing_key,
        );

        let req = TestRequest::default()
            .insert_header(("AccessToken", token.as_str()))
            .to_http_request();

        assert!(
            UnverifiedToken::<Access, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .is_ok()
        );
        assert!(
            UnverifiedToken::<Access, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .unwrap()
                .verify()
                .is_err()
        );

        let req = TestRequest::default().to_http_request();

        assert!(
            UnverifiedToken::<Access, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );
    }

    #[actix_web::test]
    async fn test_unverified_from_query() {
        let user_id = Uuid::new_v4();
        let user_email = "test1234@example.com";
        let exp = SystemTime::now() + Duration::from_secs(10);

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email: &user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(
            token_claims.encrypt(&env::CONF.token_encryption_cipher),
            &env::CONF.token_signing_key,
        );

        let req = TestRequest::default()
            .uri(&format!("/test?AccessToken={}", &token))
            .to_http_request();

        assert!(
            UnverifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_ok()
        );
        assert!(
            UnverifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .unwrap()
                .verify()
                .is_ok()
        );
        assert!(
            UnverifiedToken::<Access, FromHeader>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );
        assert!(
            UnverifiedToken::<Refresh, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );
        assert!(
            UnverifiedToken::<UserDeletion, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email: &user_email,
            expiration: exp,
            token_type: AuthTokenType::Refresh,
        };

        let token = AuthToken::sign_new(
            token_claims.encrypt(&env::CONF.token_encryption_cipher),
            &env::CONF.token_signing_key,
        );

        let req = TestRequest::default()
            .uri(&format!("/test?AccessToken={}", &token))
            .to_http_request();

        assert!(
            UnverifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_ok()
        );
        assert!(
            UnverifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .unwrap()
                .verify()
                .is_err()
        );

        let req = TestRequest::default()
            .uri(&format!("/test?RefreshToken={}", &token))
            .to_http_request();

        assert!(
            UnverifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );

        let exp = SystemTime::now() - Duration::from_secs(10);

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email: &user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(
            token_claims.encrypt(&env::CONF.token_encryption_cipher),
            &env::CONF.token_signing_key,
        );

        let req = TestRequest::default()
            .uri(&format!("/test?AccessToken={}", &token))
            .to_http_request();

        assert!(
            UnverifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_ok()
        );
        assert!(
            UnverifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .unwrap()
                .verify()
                .is_err()
        );

        let req = TestRequest::default().to_http_request();

        assert!(
            UnverifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );
    }
}
