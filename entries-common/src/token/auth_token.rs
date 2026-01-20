use crate::token::{Expiring, HmacSha256Verifier, Token, TokenError};

use base64::engine::general_purpose::URL_SAFE as b64_urlsafe;
use base64::Engine;
use hmac::Mac;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::HmacSha256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthTokenType {
    Nothing,
    Access,
    Refresh,
    SignIn,
    UserDeletion,
}

impl std::convert::TryFrom<u8> for AuthTokenType {
    type Error = TokenError;

    fn try_from(value: u8) -> Result<Self, TokenError> {
        match value {
            0 => Ok(AuthTokenType::Nothing),
            1 => Ok(AuthTokenType::Access),
            2 => Ok(AuthTokenType::Refresh),
            3 => Ok(AuthTokenType::SignIn),
            5 => Ok(AuthTokenType::UserDeletion),
            _ => Err(TokenError::WrongTokenType),
        }
    }
}

impl std::convert::From<AuthTokenType> for u8 {
    fn from(token_type: AuthTokenType) -> Self {
        match token_type {
            AuthTokenType::Nothing => 0,
            AuthTokenType::Access => 1,
            AuthTokenType::Refresh => 2,
            AuthTokenType::SignIn => 3,
            AuthTokenType::UserDeletion => 5,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthTokenClaims {
    #[serde(rename = "uid")]
    pub user_id: Uuid,
    #[serde(rename = "eml")]
    pub user_email: String,
    #[serde(rename = "exp")]
    pub expiration: u64,
    #[serde(rename = "typ")]
    pub token_type: AuthTokenType,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewAuthTokenClaims<'a> {
    #[serde(rename = "uid")]
    pub user_id: Uuid,
    #[serde(rename = "eml")]
    pub user_email: &'a str,
    #[serde(rename = "exp")]
    pub expiration: u64,
    #[serde(rename = "typ")]
    pub token_type: AuthTokenType,
}

impl Expiring for AuthTokenClaims {
    fn expiration(&self) -> u64 {
        self.expiration
    }
}

pub struct AuthToken {}

impl AuthToken {
    pub fn sign_new(claims: NewAuthTokenClaims, signing_key: &[u8]) -> String {
        let mut token_unencoded =
            serde_json::to_vec(&claims).expect("Failed to transform claims into JSON");

        let mut mac = HmacSha256::new_from_slice(signing_key).expect("HMAC key should not fail");
        mac.update(&token_unencoded);
        let signature = mac.finalize();
        token_unencoded.extend_from_slice(&signature.into_bytes());

        b64_urlsafe.encode(&token_unencoded)
    }
}

impl Token for AuthToken {
    type Claims = AuthTokenClaims;
    type Verifier = HmacSha256Verifier;

    fn token_name() -> &'static str {
        "AuthToken"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn test_sign_and_verify() {
        let user_id = Uuid::now_v7();
        let user_email = "test1234@example.com";
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signing_key = [9; 64];

        let claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(claims, &signing_key);
        let t = AuthToken::decode(&token).unwrap();
        let claims = t.verify(&signing_key).unwrap();

        assert_eq!(claims.user_id, user_id);
        assert_eq!(claims.user_email, user_email);
        assert_eq!(claims.expiration, exp,);
        assert_eq!(claims.token_type, AuthTokenType::Access);

        let claims = NewAuthTokenClaims {
            user_id: claims.user_id,
            user_email: &claims.user_email,
            expiration: claims.expiration,
            token_type: claims.token_type,
        };

        let t = AuthToken::sign_new(claims, &signing_key);

        assert!(String::from_utf8_lossy(&b64_urlsafe.decode(&t).unwrap())
            .contains(&format!("{}", exp,)));

        let t = AuthToken::decode(&t.clone()).unwrap();
        t.verify(&signing_key).unwrap();

        let claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Refresh,
        };

        let token = AuthToken::sign_new(claims, &signing_key);
        let mut t = b64_urlsafe.decode(token).unwrap();

        // Make the signature invalid
        let last_byte = t.pop().unwrap();
        if last_byte == 0x01 {
            t.push(0x02);
        } else {
            t.push(0x01);
        }

        let t = b64_urlsafe.encode(t);

        assert!(AuthToken::decode(&t).unwrap().verify(&signing_key).is_err());

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(claims, &signing_key);
        assert!(AuthToken::decode(&token)
            .unwrap()
            .verify(&signing_key)
            .is_err());
    }
}
