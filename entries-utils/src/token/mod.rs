pub mod auth_token;
pub mod budget_accept_token;
pub mod budget_access_token;
pub mod budget_invite_sender_token;

use ed25519_dalek::{PublicKey, Signature, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use sha2::Sha256;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum TokenError {
    TokenInvalid,
    TokenExpired,
    TokenMissing,
    WrongTokenType,
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

pub struct TokenParts {
    pub json: String,
    pub signature: Vec<u8>,
}

pub trait TokenSignatureVerifier {
    fn verify(json: &str, signature: &[u8], key: &[u8]) -> bool;
}

pub trait Token<'a> {
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

    fn token_name() -> &'static str;
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

pub struct HmacSha256Verifier {}

impl TokenSignatureVerifier for HmacSha256Verifier {
    fn verify(json: &str, signature: &[u8], key: &[u8]) -> bool {
        let mut mac = Hmac::<Sha256>::new(key.into());
        mac.update(json.as_bytes());

        let correct_hash = mac.finalize().into_bytes();

        let mut hashes_dont_match = 0u8;

        if correct_hash.len() != signature.len() || signature.is_empty() {
            return false;
        }

        // Do bitwise comparison to prevent timing attacks
        for (i, correct_hash_byte) in correct_hash.iter().enumerate() {
            unsafe {
                hashes_dont_match |= correct_hash_byte ^ signature.get_unchecked(i);
            }
        }

        hashes_dont_match == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hmac::{Hmac, Mac};
    use serde::{Deserialize, Serialize};
    use std::time::Duration;
    use uuid::Uuid;

    #[derive(Clone, Copy, Serialize, Deserialize)]
    struct TestClaims {
        id: Uuid,
        exp: u64,
    }

    struct TestToken {
        claims: TestClaims,
        parts: Option<TokenParts>,
    }

    impl<'a> Token<'a> for TestToken {
        type Claims = TestClaims;
        type InternalClaims = TestClaims;
        type Verifier = HmacSha256Verifier;

        fn token_name() -> &'static str {
            "TestToken"
        }

        fn from_pieces(claims: Self::InternalClaims, parts: TokenParts) -> Self {
            Self {
                claims,
                parts: Some(parts),
            }
        }

        fn expiration(&self) -> u64 {
            self.claims.exp
        }

        fn parts(&'a self) -> &'a Option<TokenParts> {
            &self.parts
        }

        fn claims(self) -> Self::Claims {
            self.claims
        }
    }

    impl TestToken {
        fn new(claims: TestClaims) -> Self {
            Self {
                claims: claims,
                parts: None,
            }
        }

        fn sign_and_encode(&self) -> String {
            let mut json_of_claims = serde_json::to_vec(&self.claims).unwrap();

            let mut mac = Hmac::<Sha256>::new((&[0; 64]).into());
            mac.update(&json_of_claims);
            let hash = hex::encode(mac.finalize().into_bytes());

            json_of_claims.push(124); // 124 is the ASCII value of the | character
            json_of_claims.extend_from_slice(&hash.into_bytes());

            base64::encode_config(json_of_claims, base64::URL_SAFE_NO_PAD)
        }
    }

    #[test]
    fn test_from_str() {
        let id = Uuid::new_v4();
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = TestToken::new(TestClaims { id, exp });
        let token = token.sign_and_encode();

        let token = TestToken::from_str(&token).unwrap();
        assert!(!token.parts.as_ref().unwrap().signature.is_empty());

        let claims = token.claims();
        assert_eq!(claims.id, id);
        assert_eq!(claims.exp, exp);
    }
}
