use entries_utils::token::{DecodedToken, Token, TokenError};

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest};
use futures::future;
use std::marker::PhantomData;

use crate::handlers::error::HttpErrorResponse;
use crate::middleware::{into_actix_error_res, TokenLocation};

pub struct SpecialAccessToken<T: Token, L: TokenLocation>(
    pub DecodedToken<T::Claims, T::Verifier>,
    PhantomData<T>,
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

        future::ok(SpecialAccessToken(decoded_token, PhantomData, PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::dev::Payload;
    use actix_web::test::TestRequest;
    use ed25519::Signer;
    use ed25519_dalek as ed25519;
    use rand::rngs::OsRng;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    use entries_utils::token::{
        budget_access_token::{BudgetAccessToken, BudgetAccessTokenClaims},
        budget_invite_sender_token::{BudgetInviteSenderToken, BudgetInviteSenderTokenClaims},
    };

    use crate::middleware::{FromHeader, FromQuery};

    #[actix_web::test]
    async fn test_from_header() {
        let kid = Uuid::new_v4();
        let bid = Uuid::new_v4();
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = BudgetAccessTokenClaims {
            key_id: kid,
            budget_id: bid,
            expiration: exp,
        };
        let claims = serde_json::to_vec(&claims).unwrap();
        let claims = String::from_utf8_lossy(&claims);

        let access_key_pair = ed25519::SigningKey::generate(&mut OsRng);
        let access_public_key = access_key_pair.verifying_key().to_bytes();
        let signature = hex::encode(access_key_pair.sign(claims.as_bytes()).to_bytes());
        let token = base64::encode_config(format!("{claims}|{signature}"), base64::URL_SAFE_NO_PAD);

        let req = TestRequest::default()
            .insert_header(("BudgetAccessToken", token.as_str()))
            .to_http_request();

        assert!(
            SpecialAccessToken::<BudgetAccessToken, FromHeader>::from_request(
                &req,
                &mut Payload::None
            )
            .await
            .is_ok()
        );
        assert!(
            SpecialAccessToken::<BudgetInviteSenderToken, FromHeader>::from_request(
                &req,
                &mut Payload::None
            )
            .await
            .is_err()
        );
        assert!(
            SpecialAccessToken::<BudgetAccessToken, FromQuery>::from_request(
                &req,
                &mut Payload::None
            )
            .await
            .is_err()
        );

        let t = SpecialAccessToken::<BudgetAccessToken, FromHeader>::from_request(
            &req,
            &mut Payload::None,
        )
        .await
        .unwrap();

        let c = t.0.verify(&access_public_key).unwrap();

        assert_eq!(c.key_id, kid);
        assert_eq!(c.budget_id, bid);
        assert_eq!(c.expiration, exp);

        let mut signature = hex::encode(access_key_pair.sign(claims.as_bytes()).to_bytes());

        // Make the signature invalid
        let last_char = signature.pop().unwrap();
        if last_char == 'a' {
            signature.push('b');
        } else {
            signature.push('a');
        }

        let token = base64::encode_config(format!("{claims}|{signature}"), base64::URL_SAFE_NO_PAD);

        let req = TestRequest::default()
            .insert_header(("BudgetAccessToken", token.as_str()))
            .to_http_request();

        let t = SpecialAccessToken::<BudgetAccessToken, FromHeader>::from_request(
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

        let claims = BudgetAccessTokenClaims {
            key_id: kid,
            budget_id: bid,
            expiration: exp,
        };
        let claims = serde_json::to_vec(&claims).unwrap();
        let claims = String::from_utf8_lossy(&claims);

        let signature = hex::encode(access_key_pair.sign(claims.as_bytes()).to_bytes());
        let token = base64::encode_config(format!("{claims}|{signature}"), base64::URL_SAFE_NO_PAD);

        let req = TestRequest::default()
            .insert_header(("BudgetAccessToken", token.as_str()))
            .to_http_request();

        let t = SpecialAccessToken::<BudgetAccessToken, FromHeader>::from_request(
            &req,
            &mut Payload::None,
        )
        .await
        .unwrap();

        assert!(t.0.verify(&access_public_key).is_err());
    }

    #[actix_web::test]
    async fn test_from_query() {
        let iid = Uuid::new_v4();
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = BudgetInviteSenderTokenClaims {
            invite_id: iid,
            expiration: exp,
        };
        let claims = serde_json::to_vec(&claims).unwrap();
        let claims = String::from_utf8_lossy(&claims);

        let invite_key_pair = ed25519::SigningKey::generate(&mut OsRng);
        let invite_public_key = invite_key_pair.verifying_key().to_bytes();
        let signature = hex::encode(invite_key_pair.sign(claims.as_bytes()).to_bytes());
        let token = base64::encode_config(format!("{claims}|{signature}"), base64::URL_SAFE_NO_PAD);

        let req = TestRequest::default()
            .uri(&format!("/test?BudgetInviteSenderToken={}", &token))
            .to_http_request();

        assert!(
            SpecialAccessToken::<BudgetInviteSenderToken, FromQuery>::from_request(
                &req,
                &mut Payload::None
            )
            .await
            .is_ok()
        );
        assert!(
            SpecialAccessToken::<BudgetAccessToken, FromQuery>::from_request(
                &req,
                &mut Payload::None
            )
            .await
            .is_err()
        );
        assert!(
            SpecialAccessToken::<BudgetInviteSenderToken, FromHeader>::from_request(
                &req,
                &mut Payload::None
            )
            .await
            .is_err()
        );

        let t = SpecialAccessToken::<BudgetInviteSenderToken, FromQuery>::from_request(
            &req,
            &mut Payload::None,
        )
        .await
        .unwrap();

        assert!(t.0.verify(&invite_public_key).is_ok());

        let mut signature = hex::encode(invite_key_pair.sign(claims.as_bytes()).to_bytes());

        // Make the signature invalid
        let last_char = signature.pop().unwrap();
        if last_char == 'a' {
            signature.push('b');
        } else {
            signature.push('a');
        }

        let token = base64::encode_config(format!("{claims}|{signature}"), base64::URL_SAFE_NO_PAD);

        let req = TestRequest::default()
            .uri(&format!("/test?BudgetInviteSenderToken={}", &token))
            .to_http_request();

        let t = SpecialAccessToken::<BudgetInviteSenderToken, FromQuery>::from_request(
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

        let claims = BudgetInviteSenderTokenClaims {
            invite_id: iid,
            expiration: exp,
        };
        let claims = serde_json::to_vec(&claims).unwrap();
        let claims = String::from_utf8_lossy(&claims);

        let signature = hex::encode(invite_key_pair.sign(claims.as_bytes()).to_bytes());
        let token = base64::encode_config(format!("{claims}|{signature}"), base64::URL_SAFE_NO_PAD);

        let req = TestRequest::default()
            .uri(&format!("/test?BudgetInviteSenderToken={}", &token))
            .to_http_request();

        let t = SpecialAccessToken::<BudgetInviteSenderToken, FromQuery>::from_request(
            &req,
            &mut Payload::None,
        )
        .await
        .unwrap();

        assert!(t.0.verify(&invite_public_key).is_err());
    }
}
