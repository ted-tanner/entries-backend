use entries_common::token::{DecodedToken, Token, TokenError};

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest};
use futures::future;
use std::marker::PhantomData;

use crate::handlers::error::HttpErrorResponse;
use crate::middleware::{into_actix_error_res, TokenLocation};

pub struct SpecialAccessToken<T: Token, L: TokenLocation>(
    pub DecodedToken<T::Claims, T::Verifier>,
    PhantomData<L>,
);

impl<T, L> FromRequest for SpecialAccessToken<T, L>
where
    T: Token,
    L: TokenLocation,
{
    type Error = HttpErrorResponse;
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

        let decoded_token = into_actix_error_res(T::decode(token));

        let decoded_token = match decoded_token {
            Ok(t) => t,
            Err(e) => return future::err(e),
        };

        future::ok(SpecialAccessToken(decoded_token, PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::dev::Payload;
    use actix_web::test::TestRequest;
    use base64::engine::general_purpose::URL_SAFE as b64_urlsafe;
    use base64::Engine;
    use ed25519_dalek as ed25519;
    use ed25519_dalek::Signer;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    use entries_common::threadrand::SecureRng;
    use entries_common::token::{
        container_access_token::{ContainerAccessToken, ContainerAccessTokenClaims},
        container_invite_sender_token::{
            ContainerInviteSenderToken, ContainerInviteSenderTokenClaims,
        },
    };

    use crate::middleware::{FromHeader, FromQuery};

    #[actix_web::test]
    async fn test_from_header() {
        let kid = Uuid::now_v7();
        let cid = Uuid::now_v7();
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = ContainerAccessTokenClaims {
            key_id: kid,
            container_id: cid,
            expiration: exp,
        };

        let claims = serde_json::to_vec(&claims).unwrap();
        let mut token = claims.clone();

        let access_key_pair = ed25519::SigningKey::generate(SecureRng::get_ref());
        let access_public_key = access_key_pair.verifying_key().to_bytes();
        let signature = access_key_pair.sign(&claims).to_bytes();
        token.extend_from_slice(&signature);
        let token = b64_urlsafe.encode(token);

        let req = TestRequest::default()
            .insert_header(("ContainerAccessToken", token.as_str()))
            .to_http_request();

        assert!(
            SpecialAccessToken::<ContainerAccessToken, FromHeader>::from_request(
                &req,
                &mut Payload::None
            )
            .await
            .is_ok()
        );
        assert!(
            SpecialAccessToken::<ContainerInviteSenderToken, FromHeader>::from_request(
                &req,
                &mut Payload::None
            )
            .await
            .is_err()
        );
        assert!(
            SpecialAccessToken::<ContainerAccessToken, FromQuery>::from_request(
                &req,
                &mut Payload::None
            )
            .await
            .is_err()
        );

        let t = SpecialAccessToken::<ContainerAccessToken, FromHeader>::from_request(
            &req,
            &mut Payload::None,
        )
        .await
        .unwrap();

        let c = t.0.verify(&access_public_key).unwrap();

        assert_eq!(c.key_id, kid);
        assert_eq!(c.container_id, cid);
        assert_eq!(c.expiration, exp);

        let mut signature = Vec::from(access_key_pair.sign(&claims).to_bytes());

        // Make the signature invalid
        let last_byte = signature.pop().unwrap();
        if last_byte == 0x01 {
            signature.push(0x02);
        } else {
            signature.push(0x01);
        }

        let mut token = claims.clone();
        token.extend_from_slice(&signature);
        let token = b64_urlsafe.encode(token);

        let req = TestRequest::default()
            .insert_header(("ContainerAccessToken", token.as_str()))
            .to_http_request();

        let t = SpecialAccessToken::<ContainerAccessToken, FromHeader>::from_request(
            &req,
            &mut Payload::None,
        )
        .await
        .unwrap();

        assert!(t.0.verify(&access_public_key).is_err());

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = ContainerAccessTokenClaims {
            key_id: kid,
            container_id: cid,
            expiration: exp,
        };
        let claims = serde_json::to_vec(&claims).unwrap();
        let mut token = claims.clone();

        let signature = access_key_pair.sign(&claims).to_bytes();
        token.extend_from_slice(&signature);
        let token = b64_urlsafe.encode(token);

        let req = TestRequest::default()
            .insert_header(("ContainerAccessToken", token.as_str()))
            .to_http_request();

        let t = SpecialAccessToken::<ContainerAccessToken, FromHeader>::from_request(
            &req,
            &mut Payload::None,
        )
        .await
        .unwrap();

        assert!(t.0.verify(&access_public_key).is_err());
    }

    #[actix_web::test]
    async fn test_from_query() {
        let iid = Uuid::now_v7();
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = ContainerInviteSenderTokenClaims {
            invite_id: iid,
            expiration: exp,
        };
        let claims = serde_json::to_vec(&claims).unwrap();
        let mut token = claims.clone();

        let invite_key_pair = ed25519::SigningKey::generate(SecureRng::get_ref());
        let invite_public_key = invite_key_pair.verifying_key().to_bytes();
        let signature = invite_key_pair.sign(&claims).to_bytes();
        token.extend_from_slice(&signature);
        let token = b64_urlsafe.encode(token);

        let req = TestRequest::default()
            .uri(&format!("/test?ContainerInviteSenderToken={}", &token))
            .to_http_request();

        assert!(
            SpecialAccessToken::<ContainerInviteSenderToken, FromQuery>::from_request(
                &req,
                &mut Payload::None
            )
            .await
            .is_ok()
        );
        assert!(
            SpecialAccessToken::<ContainerAccessToken, FromQuery>::from_request(
                &req,
                &mut Payload::None
            )
            .await
            .is_err()
        );
        assert!(
            SpecialAccessToken::<ContainerInviteSenderToken, FromHeader>::from_request(
                &req,
                &mut Payload::None
            )
            .await
            .is_err()
        );

        let t = SpecialAccessToken::<ContainerInviteSenderToken, FromQuery>::from_request(
            &req,
            &mut Payload::None,
        )
        .await
        .unwrap();

        assert!(t.0.verify(&invite_public_key).is_ok());

        let mut signature = Vec::from(invite_key_pair.sign(&claims).to_bytes());

        // Make the signature invalid
        let last_byte = signature.pop().unwrap();
        if last_byte == 0x01 {
            signature.push(0x02);
        } else {
            signature.push(0x01);
        }

        let mut token = claims.clone();
        token.extend_from_slice(&signature);
        let token = b64_urlsafe.encode(token);

        let req = TestRequest::default()
            .uri(&format!("/test?ContainerInviteSenderToken={}", &token))
            .to_http_request();

        let t = SpecialAccessToken::<ContainerInviteSenderToken, FromQuery>::from_request(
            &req,
            &mut Payload::None,
        )
        .await
        .unwrap();

        assert!(t.0.verify(&invite_public_key).is_err());

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = ContainerInviteSenderTokenClaims {
            invite_id: iid,
            expiration: exp,
        };
        let claims = serde_json::to_vec(&claims).unwrap();
        let mut token = claims.clone();

        let signature = invite_key_pair.sign(&claims).to_bytes();
        token.extend_from_slice(&signature);
        let token = b64_urlsafe.encode(token);

        let req = TestRequest::default()
            .uri(&format!("/test?ContainerInviteSenderToken={}", &token))
            .to_http_request();

        let t = SpecialAccessToken::<ContainerInviteSenderToken, FromQuery>::from_request(
            &req,
            &mut Payload::None,
        )
        .await
        .unwrap();

        assert!(t.0.verify(&invite_public_key).is_err());
    }
}
