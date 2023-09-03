pub mod auth_token;
pub mod budget_accept_token;
pub mod budget_access_token;
pub mod budget_invite_sender_token;

use base64::engine::general_purpose::URL_SAFE as b64_urlsafe;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey, SIGNATURE_LENGTH};
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use sha2::Sha256;
use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH};

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
    fn verify(json: &str, signature: &[u8], key: &[u8]) -> bool;
}

pub struct DecodedToken<C, V>
where
    C: Expiring + DeserializeOwned,
    V: TokenSignatureVerifier,
{
    pub json: String,
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
        let decoded_token = b64_urlsafe
            .decode(token)
            .map_err(|_| TokenError::TokenInvalid)?;

        let Ok(token_str) = std::str::from_utf8(&decoded_token) else {
            return Err(TokenError::TokenInvalid);
        };

        let Some((claims_json, signature)) = token_str.rsplit_once('|') else {
            return Err(TokenError::TokenInvalid);
        };

        let signature = hex::decode(signature).map_err(|_| TokenError::TokenInvalid)?;
        let claims = serde_json::from_str::<Self::Claims>(claims_json)
            .map_err(|_| TokenError::TokenInvalid)?;

        Ok(DecodedToken {
            json: String::from(claims_json),
            signature,
            claims,
            phantom: PhantomData,
        })
    }
}

pub struct Ed25519Verifier {}

impl TokenSignatureVerifier for Ed25519Verifier {
    fn verify(json: &str, signature: &[u8], key: &[u8]) -> bool {
        if signature.len() != SIGNATURE_LENGTH {
            return false;
        }

        let key = VerifyingKey::from_bytes(match key.try_into() {
            Ok(k) => k,
            Err(_) => return false,
        });

        let Ok(key) = key else {
            return false;
        };

        let signature = Signature::from_bytes(match signature.try_into() {
            Ok(s) => s,
            Err(_) => return false,
        });

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

    use ed25519_dalek::{Signer, SigningKey};
    use hmac::{Hmac, Mac};
    use rand::rngs::OsRng;
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
        pub fn sign_new(claims: TestClaims, signing_key: &[u8; 64]) -> String {
            let mut json_of_claims =
                serde_json::to_vec(&claims).expect("Failed to transform claims into JSON");

            let mut mac = Hmac::<Sha256>::new(signing_key.into());
            mac.update(&json_of_claims);
            let hash = hex::encode(mac.finalize().into_bytes());

            json_of_claims.push(b'|');
            json_of_claims.extend_from_slice(&hash.into_bytes());

            b64_urlsafe.encode(json_of_claims)
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
        pub fn sign_new(claims: TestClaims, keypair: &SigningKey) -> String {
            let mut json_of_claims =
                serde_json::to_vec(&claims).expect("Failed to transform claims into JSON");

            let hash = hex::encode(keypair.sign(&json_of_claims).to_bytes());

            json_of_claims.push(b'|');
            json_of_claims.extend_from_slice(&hash.into_bytes());

            b64_urlsafe.encode(json_of_claims)
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
        let id = Uuid::new_v4();
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
        let id = Uuid::new_v4();
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
        let id = Uuid::new_v4();
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
        let id = Uuid::new_v4();
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let keypair = SigningKey::generate(&mut OsRng);
        let pub_key = keypair.verifying_key();

        let mut token = TestTokenEd25519::sign_new(TestClaims { id, exp }, &keypair);
        let t = TestTokenEd25519::decode(&token).unwrap();
        let claims = t.verify(pub_key.as_bytes()).unwrap();

        assert_eq!(claims.id, id);
        assert_eq!(claims.exp, exp);

        make_signature_invalid(&mut token);
        assert!(TestTokenEd25519::decode(&token)
            .unwrap()
            .verify(pub_key.as_bytes())
            .is_err());

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = TestTokenEd25519::sign_new(TestClaims { id, exp }, &keypair);
        assert!(TestTokenEd25519::decode(&token)
            .unwrap()
            .verify(pub_key.as_bytes())
            .is_err());
    }
}
