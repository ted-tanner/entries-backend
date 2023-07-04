use crate::token::{Expiring, HmacSha256Verifier, Token, TokenError};

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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct PrivateAuthTokenClaims {
    user_id: Uuid,
    email: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct NewPrivateAuthTokenClaims<'a> {
    user_id: Uuid,
    email: &'a str,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthTokenClaims {
    pub user_id: Uuid,
    pub user_email: String,
    pub expiration: u64,
    pub token_type: AuthTokenType,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewAuthTokenClaims<'a> {
    pub user_id: Uuid,
    pub user_email: &'a str,
    pub expiration: SystemTime,
    pub token_type: AuthTokenType,
}

impl<'a> NewAuthTokenClaims<'a> {
    pub fn encrypt(&self, cipher: &Aes128Gcm) -> AuthTokenEncryptedClaims {
        let private_claims = NewPrivateAuthTokenClaims {
            user_id: self.user_id,
            email: self.user_email,
        };

        let private_claims_json = serde_json::to_vec(&private_claims)
            .expect("Failed to transform private claims into JSON");

        let nonce: [u8; 12] = OsRng.gen();

        let encrypted_private_claims = cipher
            .encrypt((&nonce).into(), private_claims_json.as_ref())
            .expect("Failed to encrypt private token claims");

        let exp = self
            .expiration
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_secs();

        AuthTokenEncryptedClaims {
            exp,

            nnc: base64::encode(nonce),
            enc: base64::encode(encrypted_private_claims),

            typ: self.token_type.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthTokenEncryptedClaims {
    pub exp: u64,    // Expiration
    pub nnc: String, // Nonce
    pub enc: String, // Encrypted Data
    pub typ: u8,     // Token Type
}

impl Expiring for AuthTokenEncryptedClaims {
    fn expiration(&self) -> u64 {
        self.exp
    }
}

impl AuthTokenEncryptedClaims {
    pub fn decrypt(&self, cipher: &Aes128Gcm) -> Result<AuthTokenClaims, TokenError> {
        let nonce = base64::decode(&self.nnc).map_err(|_| TokenError::TokenInvalid)?;
        let private_claims = base64::decode(&self.enc).map_err(|_| TokenError::TokenInvalid)?;

        let decrypted_self_bytes = cipher
            .decrypt((&*nonce).into(), private_claims.as_ref())
            .map_err(|_| TokenError::TokenInvalid)?;

        let decrypted_self_json_str =
            String::from_utf8(decrypted_self_bytes).map_err(|_| TokenError::TokenInvalid)?;

        let decrypted_self =
            serde_json::from_str::<PrivateAuthTokenClaims>(&decrypted_self_json_str)
                .map_err(|_| TokenError::TokenInvalid)?;

        let token_type = self.typ.try_into().map_err(|_| TokenError::TokenInvalid)?;

        let claims = AuthTokenClaims {
            user_id: decrypted_self.user_id,
            user_email: decrypted_self.email,
            expiration: self.exp,
            token_type,
        };

        Ok(claims)
    }
}

pub struct AuthToken {}

impl AuthToken {
    pub fn sign_new(encrypted_claims: AuthTokenEncryptedClaims, signing_key: &[u8; 64]) -> String {
        let mut json_of_claims =
            serde_json::to_vec(&encrypted_claims).expect("Failed to transform claims into JSON");

        let mut mac = Hmac::<Sha256>::new(signing_key.into());
        mac.update(&json_of_claims);
        let hash = hex::encode(mac.finalize().into_bytes());

        json_of_claims.push(b'|');
        json_of_claims.extend_from_slice(&hash.into_bytes());

        base64::encode_config(json_of_claims, base64::URL_SAFE)
    }
}

impl Token for AuthToken {
    type Claims = AuthTokenEncryptedClaims;
    type Verifier = HmacSha256Verifier;

    fn token_name() -> &'static str {
        "AuthToken"
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

        let claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(claims.encrypt(&encryption_key), &signing_key);
        assert!(!String::from_utf8_lossy(&base64::decode(&token).unwrap()).contains(user_email));

        let t = AuthToken::decode(&token).unwrap();
        let claims = t.verify(&signing_key).unwrap();
        let decrypted_claims = claims.decrypt(&encryption_key).unwrap();

        assert_eq!(decrypted_claims.user_id, user_id);
        assert_eq!(decrypted_claims.user_email, user_email);
        assert_eq!(
            decrypted_claims.expiration,
            exp.duration_since(UNIX_EPOCH).unwrap().as_secs()
        );
        assert_eq!(decrypted_claims.token_type, AuthTokenType::Access);

        let decrypted_claims = NewAuthTokenClaims {
            user_id: decrypted_claims.user_id,
            user_email: &decrypted_claims.user_email,
            expiration: UNIX_EPOCH + Duration::from_secs(decrypted_claims.expiration),
            token_type: decrypted_claims.token_type,
        };

        let encrypted_claims = decrypted_claims.encrypt(&encryption_key);
        let t = AuthToken::sign_new(encrypted_claims.clone(), &signing_key);

        assert!(
            String::from_utf8_lossy(&base64::decode(&t).unwrap()).contains(&format!(
                "{}",
                exp.duration_since(UNIX_EPOCH).unwrap().as_secs()
            ))
        );

        let t = AuthToken::decode(&t.clone()).unwrap();

        assert_eq!(t.claims.enc, encrypted_claims.enc);
        assert_eq!(t.claims.exp, encrypted_claims.exp);
        assert_eq!(t.claims.nnc, encrypted_claims.nnc);
        assert_eq!(t.claims.typ, encrypted_claims.typ);

        let claims = t.verify(&signing_key).unwrap();

        assert_eq!(claims.enc, encrypted_claims.enc);
        assert_eq!(claims.exp, encrypted_claims.exp);
        assert_eq!(claims.nnc, encrypted_claims.nnc);
        assert_eq!(claims.typ, encrypted_claims.typ);

        let claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Refresh,
        };

        let token = AuthToken::sign_new(claims.encrypt(&encryption_key), &signing_key);
        let mut t = base64::decode_config(token, base64::URL_SAFE).unwrap();

        // Make the signature invalid
        let last_char = t.pop().unwrap();
        if last_char == b'a' {
            t.push(b'b');
        } else {
            t.push(b'a');
        }

        let t = base64::encode_config(t, base64::URL_SAFE);

        assert!(AuthToken::decode(&t).unwrap().verify(&signing_key).is_err());

        let exp = SystemTime::now() - Duration::from_secs(10);

        let claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: exp,
            token_type: AuthTokenType::Access,
        };

        let token = AuthToken::sign_new(claims.encrypt(&encryption_key), &signing_key);
        assert!(AuthToken::decode(&token)
            .unwrap()
            .verify(&signing_key)
            .is_err());
    }
}
