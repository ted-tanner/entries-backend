use entries_common::token::auth_token::{AuthToken, AuthTokenClaims, AuthTokenType};
use entries_common::token::{DecodedToken, Token, TokenError};

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest};
use futures::future;
use std::marker::PhantomData;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::env;
use crate::handlers::error::HttpErrorResponse;
use crate::middleware::{into_actix_error_res, TokenLocation};

pub trait RequestAuthTokenType {
    fn token_name() -> &'static str;
    fn token_type() -> AuthTokenType;
    #[allow(dead_code)]
    fn token_lifetime() -> Duration;
}

pub struct Access {}
pub struct Refresh {}
pub struct SignIn {}
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

#[derive(Debug)]
pub struct UnverifiedToken<T: RequestAuthTokenType, L: TokenLocation> {
    pub decoded: AuthDecodedToken,
    pub from_cookie: bool,
    _marker: PhantomData<(T, L)>,
}

impl<T, L> UnverifiedToken<T, L>
where
    T: RequestAuthTokenType,
    L: TokenLocation,
{
    pub fn verify(&self) -> Result<AuthTokenClaims, TokenError> {
        verify_token(&self.decoded, T::token_type())
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
            Ok((decoded, from_cookie)) => future::ok(UnverifiedToken {
                decoded,
                from_cookie,
                _marker: PhantomData,
            }),
            Err(e) => future::err(e),
        }
    }
}

#[derive(Debug)]
pub struct VerifiedToken<T: RequestAuthTokenType, L: TokenLocation> {
    pub claims: AuthTokenClaims,
    #[allow(dead_code)]
    pub from_cookie: bool,
    _marker: PhantomData<(T, L)>,
}

impl<T, L> FromRequest for VerifiedToken<T, L>
where
    T: RequestAuthTokenType,
    L: TokenLocation,
{
    type Error = HttpErrorResponse;
    type Future = future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let (decoded_token, from_cookie) =
            match into_actix_error_res(get_and_decode_token::<T, L>(req)) {
                Ok(t) => t,
                Err(e) => return future::err(e),
            };

        let claims = match into_actix_error_res(verify_token(&decoded_token, T::token_type())) {
            Ok(c) => c,
            Err(e) => return future::err(e),
        };

        future::ok(VerifiedToken {
            claims,
            from_cookie,
            _marker: PhantomData,
        })
    }
}

#[inline]
fn get_and_decode_token<T, L>(req: &HttpRequest) -> Result<(AuthDecodedToken, bool), TokenError>
where
    T: RequestAuthTokenType,
    L: TokenLocation,
{
    let extracted = match L::get_from_request(req, T::token_name()) {
        Some(h) => h,
        None => return Err(TokenError::TokenMissing),
    };

    AuthToken::decode(extracted.value.as_ref()).map(|t| (t, extracted.from_cookie))
}

#[inline]
fn verify_token(
    decoded_token: &AuthDecodedToken,
    expected_type: AuthTokenType,
) -> Result<AuthTokenClaims, TokenError> {
    let claims = decoded_token.verify(&env::CONF.token_signing_key)?;

    if claims.token_type != expected_type {
        return Err(TokenError::WrongTokenType);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Failed to fetch system time")
        .as_secs();

    if claims.expiration <= now {
        return Err(TokenError::TokenExpired);
    }

    Ok(claims.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::cookie::Cookie;
    use actix_web::dev::Payload;
    use actix_web::test::TestRequest;
    use uuid::Uuid;

    use entries_common::token::auth_token::{AuthToken, NewAuthTokenClaims};

    use crate::middleware::{FromHeaderOrCookie, FromQuery};

    #[actix_web::test]
    async fn test_verified_from_header() {
        let user_id = Uuid::now_v7();
        let user_email = "test1234@example.com";
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::default()
            .insert_header(("AccessToken", token.as_str()))
            .to_http_request();

        assert!(VerifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_ok());
        assert!(
            VerifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );
        assert!(VerifiedToken::<Refresh, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_err());
        assert!(
            VerifiedToken::<UserDeletion, FromHeaderOrCookie>::from_request(
                &req,
                &mut Payload::None
            )
            .await
            .is_err()
        );

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Refresh,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::default()
            .insert_header(("AccessToken", token.as_str()))
            .to_http_request();

        assert!(VerifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_err());

        let req = TestRequest::default()
            .insert_header(("RefreshToken", token.as_str()))
            .to_http_request();

        assert!(VerifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_err());

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::default()
            .insert_header(("AccessToken", token.as_str()))
            .to_http_request();

        assert!(VerifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_err());

        let req = TestRequest::default().to_http_request();

        assert!(VerifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_err());
    }

    #[actix_web::test]
    async fn test_verified_from_query() {
        let user_id = Uuid::now_v7();
        let user_email = "test1234@example.com";
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::default()
            .uri(&format!("/test?AccessToken={}", &token))
            .to_http_request();

        assert!(
            VerifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_ok()
        );
        assert!(VerifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_err());
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
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Refresh,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

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

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

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
        let user_id = Uuid::now_v7();
        let user_email = "test1234@example.com";
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::default()
            .insert_header(("AccessToken", token.as_str()))
            .to_http_request();

        assert!(UnverifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_ok());
        assert!(UnverifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .unwrap()
        .verify()
        .is_ok());
        assert!(
            UnverifiedToken::<Access, FromQuery>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );
        assert!(
            UnverifiedToken::<Refresh, FromHeaderOrCookie>::from_request(&req, &mut Payload::None)
                .await
                .is_err()
        );
        assert!(
            UnverifiedToken::<UserDeletion, FromHeaderOrCookie>::from_request(
                &req,
                &mut Payload::None
            )
            .await
            .is_err()
        );

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Refresh,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::default()
            .insert_header(("AccessToken", token.as_str()))
            .to_http_request();

        assert!(UnverifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_ok());
        assert!(UnverifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .unwrap()
        .verify()
        .is_err());

        let req = TestRequest::default()
            .insert_header(("RefreshToken", token.as_str()))
            .to_http_request();

        assert!(UnverifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_err());

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::default()
            .insert_header(("AccessToken", token.as_str()))
            .to_http_request();

        assert!(UnverifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_ok());
        assert!(UnverifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .unwrap()
        .verify()
        .is_err());

        let req = TestRequest::default().to_http_request();

        assert!(UnverifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_err());
    }

    #[actix_web::test]
    async fn test_unverified_from_query() {
        let user_id = Uuid::now_v7();
        let user_email = "test1234@example.com";
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

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
        assert!(UnverifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_err());
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
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Refresh,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

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

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

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

    #[actix_web::test]
    async fn test_verified_from_cookie() {
        let user_id = Uuid::now_v7();
        let user_email = "test1234@example.com";
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::default()
            .cookie(Cookie::build("AccessToken", token.as_str()).finish())
            .to_http_request();

        let verified_token =
            VerifiedToken::<Access, FromHeaderOrCookie>::from_request(&req, &mut Payload::None)
                .await
                .unwrap();

        assert_eq!(verified_token.claims.user_id, user_id);
        assert_eq!(verified_token.claims.user_email, user_email);
        assert!(
            verified_token.from_cookie,
            "Token should be marked as from cookie"
        );

        // Test Refresh token from cookie
        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Refresh,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::default()
            .cookie(Cookie::build("RefreshToken", token.as_str()).finish())
            .to_http_request();

        let verified_token =
            VerifiedToken::<Refresh, FromHeaderOrCookie>::from_request(&req, &mut Payload::None)
                .await
                .unwrap();

        assert_eq!(verified_token.claims.user_id, user_id);
        assert!(
            verified_token.from_cookie,
            "Refresh token should be marked as from cookie"
        );

        // Test SignIn token from cookie
        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::SignIn,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::default()
            .cookie(Cookie::build("SignInToken", token.as_str()).finish())
            .to_http_request();

        let verified_token =
            VerifiedToken::<SignIn, FromHeaderOrCookie>::from_request(&req, &mut Payload::None)
                .await
                .unwrap();

        assert_eq!(verified_token.claims.user_id, user_id);
        assert!(
            verified_token.from_cookie,
            "SignIn token should be marked as from cookie"
        );

        // Test missing cookie
        let req = TestRequest::default().to_http_request();

        assert!(VerifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_err());
    }

    #[actix_web::test]
    async fn test_unverified_from_cookie() {
        let user_id = Uuid::now_v7();
        let user_email = "test1234@example.com";
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::default()
            .cookie(Cookie::build("AccessToken", token.as_str()).finish())
            .to_http_request();

        let unverified_token =
            UnverifiedToken::<Access, FromHeaderOrCookie>::from_request(&req, &mut Payload::None)
                .await
                .unwrap();

        assert!(
            unverified_token.from_cookie,
            "Token should be marked as from cookie"
        );
        assert!(unverified_token.verify().is_ok());

        // Test Refresh token from cookie
        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Refresh,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::default()
            .cookie(Cookie::build("RefreshToken", token.as_str()).finish())
            .to_http_request();

        let unverified_token =
            UnverifiedToken::<Refresh, FromHeaderOrCookie>::from_request(&req, &mut Payload::None)
                .await
                .unwrap();

        assert!(
            unverified_token.from_cookie,
            "Refresh token should be marked as from cookie"
        );
        assert!(unverified_token.verify().is_ok());

        // Test SignIn token from cookie
        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::SignIn,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::default()
            .cookie(Cookie::build("SignInToken", token.as_str()).finish())
            .to_http_request();

        let unverified_token =
            UnverifiedToken::<SignIn, FromHeaderOrCookie>::from_request(&req, &mut Payload::None)
                .await
                .unwrap();

        assert!(
            unverified_token.from_cookie,
            "SignIn token should be marked as from cookie"
        );
        assert!(unverified_token.verify().is_ok());

        // Test missing cookie
        let req = TestRequest::default().to_http_request();

        assert!(UnverifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_err());
    }

    #[actix_web::test]
    async fn test_header_takes_precedence_over_cookie() {
        let user_id = Uuid::now_v7();
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create two different tokens - one for header, one for cookie
        let header_token_claims = NewAuthTokenClaims {
            user_id,
            user_email: "header@example.com",
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let cookie_token_claims = NewAuthTokenClaims {
            user_id,
            user_email: "cookie@example.com",
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let header_token = AuthToken::sign_new(header_token_claims, &env::CONF.token_signing_key);
        let cookie_token = AuthToken::sign_new(cookie_token_claims, &env::CONF.token_signing_key);

        // Request with both header and cookie - header should take precedence
        let req = TestRequest::default()
            .insert_header(("AccessToken", header_token.as_str()))
            .cookie(Cookie::build("AccessToken", cookie_token.as_str()).finish())
            .to_http_request();

        let verified_token =
            VerifiedToken::<Access, FromHeaderOrCookie>::from_request(&req, &mut Payload::None)
                .await
                .unwrap();

        // Should use header token (email should be "header@example.com")
        assert_eq!(verified_token.claims.user_email, "header@example.com");
        assert!(
            !verified_token.from_cookie,
            "Token should NOT be marked as from cookie when header is present"
        );

        let unverified_token =
            UnverifiedToken::<Access, FromHeaderOrCookie>::from_request(&req, &mut Payload::None)
                .await
                .unwrap();

        // Should use header token
        assert_eq!(
            unverified_token.verify().unwrap().user_email,
            "header@example.com"
        );
        assert!(
            !unverified_token.from_cookie,
            "Token should NOT be marked as from cookie when header is present"
        );
    }

    #[actix_web::test]
    async fn test_cookie_with_wrong_token_type() {
        let user_id = Uuid::now_v7();
        let user_email = "test1234@example.com";
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create Refresh token but try to use it as Access token
        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Refresh,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::default()
            .cookie(Cookie::build("AccessToken", token.as_str()).finish())
            .to_http_request();

        // Should fail verification because token type doesn't match
        assert!(VerifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_err());

        // Unverified should succeed (it doesn't verify type)
        let unverified =
            UnverifiedToken::<Access, FromHeaderOrCookie>::from_request(&req, &mut Payload::None)
                .await
                .unwrap();

        assert!(unverified.from_cookie);
        // But verification should fail
        assert!(unverified.verify().is_err());
    }

    #[actix_web::test]
    async fn test_cookie_with_expired_token() {
        let user_id = Uuid::now_v7();
        let user_email = "test1234@example.com";
        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::default()
            .cookie(Cookie::build("AccessToken", token.as_str()).finish())
            .to_http_request();

        // Verified should fail because token is expired
        assert!(VerifiedToken::<Access, FromHeaderOrCookie>::from_request(
            &req,
            &mut Payload::None
        )
        .await
        .is_err());

        // Unverified should succeed (it doesn't verify expiration)
        let unverified =
            UnverifiedToken::<Access, FromHeaderOrCookie>::from_request(&req, &mut Payload::None)
                .await
                .unwrap();

        assert!(unverified.from_cookie);
        // But verification should fail
        assert!(unverified.verify().is_err());
    }
}
