use crate::token::{HmacSha256Verifier, Token, TokenError, TokenParts};

use aes_gcm::{aead::Aead, Aes128Gcm};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthTokenType {
    Nothing,
    Access,
    Refresh,
    SignIn,
    UserCreation,
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
            4 => Ok(AuthTokenType::UserCreation),
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
            AuthTokenType::UserCreation => 4,
            AuthTokenType::UserDeletion => 5,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthTokenClaims {
    pub user_id: Uuid,
    pub user_email: String,
    pub expiration: u64,
    pub token_type: AuthTokenType,
}

#[repr(C)]
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthTokenEncryptedClaims {
    pub exp: u64,    // Expiration
    pub nnc: String, // Nonce
    pub enc: String, // Encrypted Data
    pub typ: u8,     // Token Type
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct PrivateAuthTokenClaims {
    uid: Uuid,
    eml: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct NewPrivateAuthTokenClaims<'a> {
    uid: Uuid,
    eml: &'a str,
}

enum AuthTokenClaimsState {
    Encrypted(AuthTokenEncryptedClaims),
    Unencrypted(AuthTokenClaims),
}

pub struct AuthToken {
    claims: AuthTokenClaimsState,
    parts: Option<TokenParts>,
}

impl AuthToken {
    pub fn new(
        user_id: Uuid,
        user_email: &str,
        expiration: SystemTime,
        token_type: AuthTokenType,
    ) -> Self {
        AuthToken {
            claims: AuthTokenClaimsState::Unencrypted(AuthTokenClaims {
                user_id,
                user_email: String::from(user_email),
                expiration: expiration
                    .duration_since(UNIX_EPOCH)
                    .expect("Unix timestamp could not be computed from expiration")
                    .as_secs(),
                token_type,
            }),
            parts: None,
        }
    }

    pub fn encrypt(&mut self, cipher: &Aes128Gcm) {
        if let AuthTokenClaimsState::Unencrypted(claims) = &self.claims {
            let private_claims = NewPrivateAuthTokenClaims {
                uid: claims.user_id,
                eml: &claims.user_email,
            };

            let private_claims_json = serde_json::to_vec(&private_claims)
                .expect("Failed to transform private claims into JSON");

            let nonce: [u8; 12] = OsRng.gen();

            let encrypted_private_claims = cipher
                .encrypt((&nonce).into(), private_claims_json.as_ref())
                .expect("Failed to encrypt private token claims");

            let claims = AuthTokenEncryptedClaims {
                exp: claims.expiration,

                nnc: base64::encode(nonce),
                enc: base64::encode(encrypted_private_claims),

                typ: claims.token_type.into(),
            };

            self.claims = AuthTokenClaimsState::Encrypted(claims);
        }
    }

    pub fn decrypt(&mut self, cipher: &Aes128Gcm) -> Result<(), TokenError> {
        if let AuthTokenClaimsState::Encrypted(claims) = &self.claims {
            let nonce = match base64::decode(&claims.nnc) {
                Ok(n) => n,
                Err(_) => return Err(TokenError::TokenInvalid),
            };

            let private_claims = match base64::decode(&claims.enc) {
                Ok(c) => c,
                Err(_) => return Err(TokenError::TokenInvalid),
            };

            let decrypted_claims_bytes =
                match cipher.decrypt((&*nonce).into(), private_claims.as_ref()) {
                    Ok(c) => c,
                    Err(_) => return Err(TokenError::TokenInvalid),
                };

            let decrypted_claims_json_str = match String::from_utf8(decrypted_claims_bytes) {
                Ok(s) => s,
                Err(_) => return Err(TokenError::TokenInvalid),
            };

            let decrypted_claims =
                match serde_json::from_str::<PrivateAuthTokenClaims>(&decrypted_claims_json_str) {
                    Ok(c) => c,
                    Err(_) => return Err(TokenError::TokenInvalid),
                };

            let token_type = match claims.typ.try_into() {
                Ok(t) => t,
                Err(_) => return Err(TokenError::TokenInvalid),
            };

            let claims = AuthTokenClaims {
                user_id: decrypted_claims.uid,
                user_email: decrypted_claims.eml,
                expiration: claims.exp,
                token_type,
            };

            self.claims = AuthTokenClaimsState::Unencrypted(claims);
        }

        Ok(())
    }

    pub fn sign_and_encode(&self, signing_key: &[u8; 64]) -> String {
        let mut json_of_claims = match &self.claims {
            AuthTokenClaimsState::Encrypted(c) => {
                serde_json::to_vec(&c).expect("Failed to transform claims into JSON")
            }
            AuthTokenClaimsState::Unencrypted(c) => {
                serde_json::to_vec(&c).expect("Failed to transform claims into JSON")
            }
        };

        let mut mac = Hmac::<Sha256>::new(signing_key.into());
        mac.update(&json_of_claims);
        let hash = hex::encode(mac.finalize().into_bytes());

        json_of_claims.push(124); // 124 is the ASCII value of the | character
        json_of_claims.extend_from_slice(&hash.into_bytes());

        base64::encode_config(json_of_claims, base64::URL_SAFE_NO_PAD)
    }
}

impl<'a> Token<'a> for AuthToken {
    type Claims = AuthTokenClaims;
    type InternalClaims = AuthTokenEncryptedClaims;
    type Verifier = HmacSha256Verifier;

    fn token_name() -> &'static str {
        "AuthToken"
    }

    fn from_pieces(claims: Self::InternalClaims, parts: TokenParts) -> Self {
        Self {
            claims: AuthTokenClaimsState::Encrypted(claims),
            parts: Some(parts),
        }
    }

    fn expiration(&self) -> u64 {
        match &self.claims {
            AuthTokenClaimsState::Encrypted(c) => c.exp,
            AuthTokenClaimsState::Unencrypted(c) => c.expiration,
        }
    }

    fn parts(&'a self) -> &'a Option<TokenParts> {
        &self.parts
    }

    fn claims(self) -> Self::Claims {
        match self.claims {
            AuthTokenClaimsState::Encrypted(c) => AuthTokenClaims {
                user_id: Uuid::nil(),
                user_email: String::new(),
                expiration: c.exp,
                token_type: c.typ.try_into().unwrap_or(AuthTokenType::Nothing),
            },
            AuthTokenClaimsState::Unencrypted(c) => c,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use aes_gcm::{aead::KeyInit, Aes128Gcm};
    use std::time::Duration;

    #[test]
    fn test_encrypt_decrypt_sign_verify() {
        let user_id = Uuid::new_v4();
        let user_email = "test1234@example.com";
        let exp = SystemTime::now() + Duration::from_secs(10);
        let encryption_key = Aes128Gcm::new(&[8; 16].into());
        let signing_key = [9; 64];

        let mut token = AuthToken::new(user_id, user_email, exp, AuthTokenType::Access);
        token.encrypt(&encryption_key);

        let t = token.sign_and_encode(&signing_key);
        assert!(!String::from_utf8_lossy(&base64::decode(&t).unwrap()).contains(user_email));

        let mut token = AuthToken::from_str(&t).unwrap();
        token.decrypt(&encryption_key).unwrap();

        let t = token.sign_and_encode(&signing_key);
        assert!(String::from_utf8_lossy(&base64::decode(t).unwrap()).contains(user_email));
        assert!(token.verify(&signing_key));

        let mut token = AuthToken::new(user_id, user_email, exp, AuthTokenType::Refresh);
        token.encrypt(&encryption_key);

        let mut t =
            base64::decode_config(token.sign_and_encode(&signing_key), base64::URL_SAFE_NO_PAD)
                .unwrap();

        // Make the signature invalid
        let last_char = t.pop().unwrap();
        if last_char == b'a' {
            t.push(b'b');
        } else {
            t.push(b'a');
        }

        let t = base64::encode_config(t, base64::URL_SAFE_NO_PAD);

        let mut token = AuthToken::from_str(&t).unwrap();
        token.encrypt(&encryption_key);
        assert!(!token.verify(&signing_key));

        let mut token = AuthToken::new(user_id, user_email, exp, AuthTokenType::Refresh);
        token.encrypt(&encryption_key);

        let t = token.sign_and_encode(&signing_key);
        let mut token = AuthToken::from_str(&t).unwrap();

        token.decrypt(&encryption_key).unwrap();
        assert!(token.verify(&signing_key));

        let exp = SystemTime::now() - Duration::from_secs(10);

        let mut token = AuthToken::new(user_id, user_email, exp, AuthTokenType::Access);
        token.encrypt(&encryption_key);

        let t = token.sign_and_encode(&signing_key);
        let mut token = AuthToken::from_str(&t).unwrap();
        token.decrypt(&encryption_key).unwrap();

        assert!(!token.verify(&signing_key));
    }
}
