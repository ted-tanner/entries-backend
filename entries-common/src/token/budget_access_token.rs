use crate::token::{Ed25519Verifier, Expiring, Token};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct BudgetAccessTokenClaims {
    #[serde(rename = "kid")]
    pub key_id: Uuid, // Budget Access Key ID
    #[serde(rename = "bid")]
    pub budget_id: Uuid,
    #[serde(rename = "exp")]
    pub expiration: u64,
}

impl Expiring for BudgetAccessTokenClaims {
    fn expiration(&self) -> u64 {
        self.expiration
    }
}

pub struct BudgetAccessToken {}

impl Token for BudgetAccessToken {
    type Claims = BudgetAccessTokenClaims;
    type Verifier = Ed25519Verifier;

    fn token_name() -> &'static str {
        "BudgetAccessToken"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::engine::general_purpose::URL_SAFE as b64_urlsafe;
    use base64::Engine;
    use ed25519_dalek as ed25519;
    use ed25519_dalek::Signer;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn test_verify() {
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

        let keypair = ed25519::SigningKey::generate(&mut rand::rngs::OsRng);
        let pub_key = keypair.verifying_key().to_bytes();

        let mut token_unencoded = claims.clone();

        let signature = keypair.sign(&token_unencoded);
        token_unencoded.extend_from_slice(&signature.to_bytes());

        let token = b64_urlsafe.encode(&token_unencoded);
        let t = BudgetAccessToken::decode(&token).unwrap();

        assert_eq!(t.claims.key_id, kid);
        assert_eq!(t.claims.budget_id, bid);
        assert_eq!(t.claims.expiration, exp);

        let verified_claims = t.verify(&pub_key).unwrap();

        assert_eq!(verified_claims.key_id, kid);
        assert_eq!(verified_claims.budget_id, bid);
        assert_eq!(verified_claims.expiration, exp);

        let mut token = claims.clone();
        token.extend_from_slice(&signature.to_bytes());

        // Make the signature invalid
        let last_byte = token.pop().unwrap();
        if last_byte == 0x01 {
            token.push(0x02);
        } else {
            token.push(0x01);
        }

        let token = b64_urlsafe.encode(&token);
        assert!(BudgetAccessToken::decode(&token)
            .unwrap()
            .verify(&pub_key)
            .is_err());

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = BudgetAccessTokenClaims {
            key_id: kid,
            budget_id: bid,
            expiration: exp,
        };
        let mut token = serde_json::to_vec(&claims).unwrap();
        let signature = keypair.sign(&token);

        token.extend_from_slice(&signature.to_bytes());

        let token = b64_urlsafe.encode(&token);
        assert!(BudgetAccessToken::decode(&token)
            .unwrap()
            .verify(&pub_key)
            .is_err());
    }
}
