pub mod auth_token;
pub mod budget_access_token;
pub mod special_access_token;

use ed25519_dalek::{PublicKey, Signature, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::de::DeserializeOwned;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug)]
pub enum TokenError {
    InvalidTokenType,
    TokenInvalid,
    TokenExpired,
    WrongTokenType,
}

pub struct TokenParts {
    pub json: String,
    pub signature: Vec<u8>,
}

impl std::error::Error for TokenError {}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::InvalidTokenType => write!(f, "InvalidTokenType"),
            TokenError::TokenInvalid => write!(f, "TokenInvalid"),
            TokenError::TokenExpired => write!(f, "TokenExpired"),
            TokenError::WrongTokenType => write!(f, "WrongTokenType"),
        }
    }
}

pub trait TokenSignatureVerifier {
    fn verify(json: &str, signature: &[u8], key: &[u8]) -> bool;
}

pub trait ClientSignedToken<'a> {
    type Claims;
    type InternalClaims: DeserializeOwned;
    type Verifier: TokenSignatureVerifier;

    fn from_str(token: &str) -> Result<Self, TokenError> where Self: Sized {
        let (claims, parts) = Self::decode(token)?;
        Ok(Self::from_pieces(claims, parts))
    }

    fn decode(token: &str) -> Result<(Self::InternalClaims, TokenParts), TokenError> {
        let decoded_token = match base64::decode_config(token.as_bytes(), base64::URL_SAFE_NO_PAD) {
            Ok(t) => t,
            Err(_) => return Err(TokenError::TokenInvalid),
        };

        let token_str = String::from_utf8_lossy(&decoded_token);
        let mut split_token = token_str.split('|');

        let signature_str = match split_token.next_back() {
            Some(h) => h,
            None => return Err(TokenError::TokenInvalid),
        };

        let signature = match hex::decode(signature_str) {
            Ok(h) => h,
            Err(_) => return Err(TokenError::TokenInvalid),
        };

        let claims_json_string = split_token.collect::<String>();
        let claims = match serde_json::from_str::<Self::InternalClaims>(&claims_json_string) {
            Ok(c) => c,
            Err(_) => return Err(TokenError::TokenInvalid),
        };

        let parts = TokenParts {
            json: claims_json_string,
            signature: signature,
        };

        Ok((claims, parts))
    }

    fn verify_for_user(&'a self, expected_user_id: Uuid, key: &[u8]) -> bool {
        if self.user_id() != expected_user_id {
            return false;
        }

        if self.expiration()
            >= SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        {
            return false;
        }

        let verified = Self::Verifier::verify(self.json(), self.signature(), key);

        verified
    }

    fn from_pieces(claims: Self::InternalClaims, parts: TokenParts) -> Self;

    fn user_id(&self) -> Uuid;
    fn expiration(&self) -> u64;
    fn claims(&self) -> Self::Claims;
    fn json(&'a self) -> &'a str;
    fn signature(&'a self) -> &'a [u8];
}

pub struct Ed25519Verifier {}

impl TokenSignatureVerifier for Ed25519Verifier {
    fn verify(json: &str, signature: &[u8], key: &[u8]) -> bool {
        if signature.len() != SIGNATURE_LENGTH {
            return false;
        }

        if key.len() != PUBLIC_KEY_LENGTH {
            return false;
        }

        let key = match PublicKey::from_bytes(key) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let signature = match Signature::from_bytes(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        match key.verify_strict(json.as_bytes(), &signature) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}
