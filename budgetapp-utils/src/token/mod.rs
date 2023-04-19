pub mod auth_token;
pub mod budget_access_token;

use ed25519_dalek::{PublicKey, Signature, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::de::DeserializeOwned;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum TokenError {
    TokenInvalid,
    TokenExpired,
    TokenMissing,
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
            TokenError::TokenInvalid => write!(f, "TokenInvalid"),
            TokenError::TokenExpired => write!(f, "TokenExpired"),
            TokenError::TokenMissing => write!(f, "TokenMissing"),
            TokenError::WrongTokenType => write!(f, "WrongTokenType"),
        }
    }
}

pub trait TokenSignatureVerifier {
    fn verify(json: &str, signature: &[u8], key: &[u8]) -> bool;
}

pub trait UserToken<'a> {
    type Claims;
    type InternalClaims: DeserializeOwned;
    type Verifier: TokenSignatureVerifier;

    fn from_str(token: &str) -> Result<Self, TokenError>
    where
        Self: Sized,
    {
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
            signature,
        };

        Ok(Self::from_pieces(claims, parts))
    }

    fn verify(&'a self, key: &[u8]) -> bool {
        if self.expiration()
            >= SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        {
            return false;
        }

        let parts = match self.parts() {
            Some(p) => p,
            None => return false,
        };

        Self::Verifier::verify(&parts.json, &parts.signature, key)
    }

    fn clear_buffers(&mut self);
    fn from_pieces(claims: Self::InternalClaims, parts: TokenParts) -> Self;

    fn expiration(&self) -> u64;
    fn parts(&'a self) -> &'a Option<TokenParts>;
    fn claims(self) -> Self::Claims;
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

        key.verify_strict(json.as_bytes(), &signature).is_ok()
    }
}
