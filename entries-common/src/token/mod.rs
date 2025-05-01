pub mod auth_token;
pub mod budget_accept_token;
pub mod budget_access_token;
pub mod budget_invite_sender_token;

use base64::engine::general_purpose::URL_SAFE as b64_urlsafe;
use base64::Engine;
use ed25519_dalek as ed25519;
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use sha2::Sha256;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub enum TokenError {
    TokenInvalid,
    TokenExpired,
    TokenMissing,
    WrongTokenType,
}

impl std::error::Error for TokenError {}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::TokenInvalid => write!(f, "TokenInvalid"),
            TokenError::TokenExpired => write!(f, "TokenExpired"),
            TokenError::TokenMissing => write!(f, "TokenMissing"),
            TokenError::WrongTokenType => write!(f, "WrongTokenType"),
        }
    }
}

pub trait Expiring {
    fn expiration(&self) -> u64;
}

pub trait TokenSignatureVerifier {
    fn signature_length() -> usize;
    fn verify(json: &[u8], signature: &[u8], key: &[u8]) -> bool;
}

#[derive(Debug)]
pub struct DecodedToken<C, V>
where
    C: Expiring + DeserializeOwned,
    V: TokenSignatureVerifier,
{
    pub json: Vec<u8>,
    pub signature: Vec<u8>,
    pub claims: C,
    phantom: PhantomData<V>,
}

impl<C, V> DecodedToken<C, V>
where
    C: Expiring + DeserializeOwned,
    V: TokenSignatureVerifier,
{
    pub fn verify(&self, key: &[u8]) -> Result<&C, TokenError> {
        if !V::verify(&self.json, &self.signature, key) {
            return Err(TokenError::TokenInvalid);
        }

        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return Err(TokenError::TokenInvalid);
        };

        if self.claims.expiration() <= now.as_secs() {
            return Err(TokenError::TokenExpired);
        }

        Ok(&self.claims)
    }
}

pub trait Token {
    type Claims: Expiring + DeserializeOwned;
    type Verifier: TokenSignatureVerifier;

    fn token_name() -> &'static str;

    fn decode(token: &str) -> Result<DecodedToken<Self::Claims, Self::Verifier>, TokenError> {
        const MAX_TOKEN_LENGTH: usize = 8192;

        if token.len() > MAX_TOKEN_LENGTH {
            return Err(TokenError::TokenInvalid);
        }

        let decoded_token = b64_urlsafe
            .decode(token)
            .map_err(|_| TokenError::TokenInvalid)?;

        if decoded_token.len() <= Self::Verifier::signature_length() {
            return Err(TokenError::TokenInvalid);
        }

        let json_len = decoded_token.len() - Self::Verifier::signature_length();
        let json = &decoded_token[..json_len];

        let signature = Vec::from(&decoded_token[json_len..]);
        let claims: Self::Claims =
            serde_json::from_slice(json).map_err(|_| TokenError::TokenInvalid)?;

        Ok(DecodedToken {
            json: Vec::from(json),
            signature,
            claims,
            phantom: PhantomData,
        })
    }
}

#[derive(Debug)]
pub struct Ed25519Verifier {}

impl TokenSignatureVerifier for Ed25519Verifier {
    fn signature_length() -> usize {
        ed25519::SIGNATURE_LENGTH
    }

    fn verify(json: &[u8], signature: &[u8], key: &[u8]) -> bool {
        let Ok(signature) = <[u8; ed25519::SIGNATURE_LENGTH]>::try_from(signature) else {
            return false;
        };

        let signature = ed25519::Signature::from(signature);

        if key.len() != ed25519::PUBLIC_KEY_LENGTH {
            return false;
        }

        let Ok(key) = key.try_into() else {
            return false;
        };

        let Ok(key) = ed25519::VerifyingKey::from_bytes(key) else {
            return false;
        };

        key.verify_strict(json, &signature).is_ok()
    }
}

#[derive(Debug)]
pub struct HmacSha256Verifier {}

impl TokenSignatureVerifier for HmacSha256Verifier {
    fn signature_length() -> usize {
        32
    }

    fn verify(json: &[u8], signature: &[u8], key: &[u8]) -> bool {
        let mut mac =
            HmacSha256::new_from_slice(key).expect("HMAC should not fail to initialize with key");
        mac.update(json);
        let correct_signature = mac.finalize().into_bytes();

        let mut signatures_dont_match = 0u8;

        if correct_signature.len() != signature.len() || signature.is_empty() {
            return false;
        }

        // Do bitwise comparison to prevent timing attacks
        for (i, correct_sig_byte) in correct_signature.iter().enumerate() {
            unsafe {
                signatures_dont_match |= correct_sig_byte ^ signature.get_unchecked(i);
            }
        }

        signatures_dont_match == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::Signer;
    use serde::{Deserialize, Serialize};
    use std::time::Duration;
    use uuid::Uuid;

    #[derive(Clone, Copy, Serialize, Deserialize)]
    struct TestClaims {
        id: Uuid,
        exp: u64,
    }

    impl Expiring for TestClaims {
        fn expiration(&self) -> u64 {
            self.exp
        }
    }

    struct TestTokenHmac {}

    impl Token for TestTokenHmac {
        type Claims = TestClaims;
        type Verifier = HmacSha256Verifier;

        fn token_name() -> &'static str {
            "TestTokenHmac"
        }
    }

    impl TestTokenHmac {
        pub fn sign_new(claims: TestClaims, signing_key: &[u8]) -> String {
            let mut token_unencoded =
                serde_json::to_vec(&claims).expect("Failed to transform claims into JSON");

            let mut mac =
                HmacSha256::new_from_slice(signing_key).expect("HMAC key should not fail");
            mac.update(&token_unencoded);
            let signature = mac.finalize();
            token_unencoded.extend_from_slice(&signature.into_bytes());

            b64_urlsafe.encode(&token_unencoded)
        }
    }

    struct TestTokenEd25519 {}

    impl Token for TestTokenEd25519 {
        type Claims = TestClaims;
        type Verifier = Ed25519Verifier;

        fn token_name() -> &'static str {
            "TestTokenEd25519"
        }
    }

    impl TestTokenEd25519 {
        pub fn sign_new(claims: TestClaims, signing_key: &ed25519::SigningKey) -> String {
            let mut token_unencoded =
                serde_json::to_vec(&claims).expect("Failed to transform claims into JSON");

            let signature = signing_key.sign(&token_unencoded);
            token_unencoded.extend_from_slice(&signature.to_bytes());

            b64_urlsafe.encode(&token_unencoded)
        }
    }

    fn make_signature_invalid(signature: &mut String) {
        let mut decoded = b64_urlsafe.decode(&signature).unwrap();

        if decoded.last().unwrap() == &b'a' {
            decoded.pop();
            decoded.push(b'b');
        } else {
            decoded.pop();
            decoded.push(b'a');
        }

        *signature = b64_urlsafe.encode(decoded);
    }

    #[test]
    fn test_from_str() {
        let id = Uuid::now_v7();
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = TestTokenHmac::sign_new(TestClaims { id, exp }, &[10; 64]);
        let t = TestTokenHmac::decode(&token).unwrap();
        let claims = t.verify(&[10; 64]).unwrap();

        assert_eq!(claims.id, id);
        assert_eq!(claims.exp, exp);
    }

    #[test]
    fn test_decode() {
        let id = Uuid::now_v7();
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = TestTokenHmac::sign_new(TestClaims { id, exp }, &[10; 64]);
        let t = TestTokenHmac::decode(&token).unwrap();

        assert_eq!(t.claims.id, id);
        assert_eq!(t.claims.exp, exp);

        let claims = t.verify(&[10; 64]).unwrap();

        assert_eq!(claims.id, id);
        assert_eq!(claims.exp, exp);
    }

    #[test]
    fn test_verify_hmac() {
        let id = Uuid::now_v7();
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let key = [2; 64];

        let mut token = TestTokenHmac::sign_new(TestClaims { id, exp }, &key);
        let t = TestTokenHmac::decode(&token).unwrap();
        let claims = t.verify(&key).unwrap();

        assert_eq!(claims.id, id);
        assert_eq!(claims.exp, exp);

        make_signature_invalid(&mut token);
        assert!(TestTokenHmac::decode(&token).unwrap().verify(&key).is_err());

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = TestTokenHmac::sign_new(TestClaims { id, exp }, &key);
        assert!(TestTokenHmac::decode(&token).unwrap().verify(&key).is_err());
    }

    #[test]
    fn test_verify_ed25519() {
        let id = Uuid::now_v7();
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let key = ed25519::SigningKey::generate(&mut crate::threadrand::SecureRng);

        let pub_key = key.verifying_key().to_bytes();

        let mut token = TestTokenEd25519::sign_new(TestClaims { id, exp }, &key);
        let t = TestTokenEd25519::decode(&token).unwrap();
        let claims = t.verify(&pub_key).unwrap();

        assert_eq!(claims.id, id);
        assert_eq!(claims.exp, exp);

        make_signature_invalid(&mut token);
        assert!(TestTokenEd25519::decode(&token)
            .unwrap()
            .verify(&pub_key)
            .is_err());

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = TestTokenEd25519::sign_new(TestClaims { id, exp }, &key);
        assert!(TestTokenEd25519::decode(&token)
            .unwrap()
            .verify(&pub_key)
            .is_err());
    }
}
