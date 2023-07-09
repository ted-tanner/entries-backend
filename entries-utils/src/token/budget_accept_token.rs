use crate::token::{Ed25519Verifier, Expiring, Token};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct BudgetAcceptTokenClaims {
    pub invite_id: Uuid, // Invitation ID
    pub key_id: Uuid,    // Budget Share Key ID
    pub budget_id: Uuid,
    pub expiration: u64,
}

impl Expiring for BudgetAcceptTokenClaims {
    fn expiration(&self) -> u64 {
        self.expiration
    }
}

pub struct BudgetAcceptToken {}

impl Token for BudgetAcceptToken {
    type Claims = BudgetAcceptTokenClaims;
    type Verifier = Ed25519Verifier;

    fn token_name() -> &'static str {
        "BudgetAcceptToken"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::engine::general_purpose::URL_SAFE as b64_urlsafe;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn test_verify() {
        let iid = Uuid::new_v4();
        let kid = Uuid::new_v4();
        let bid = Uuid::new_v4();
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = BudgetAcceptTokenClaims {
            invite_id: iid,
            key_id: kid,
            budget_id: bid,
            expiration: exp,
        };
        let claims = serde_json::to_vec(&claims).unwrap();
        let claims = String::from_utf8_lossy(&claims);

        let keypair = SigningKey::generate(&mut OsRng);
        let pub_key = keypair.verifying_key();
        let signature = hex::encode(keypair.sign(claims.as_bytes()).to_bytes());

        let token = b64_urlsafe.encode(format!("{claims}|{signature}"));
        let t = BudgetAcceptToken::decode(&token).unwrap();

        assert_eq!(t.claims.invite_id, iid);
        assert_eq!(t.claims.key_id, kid);
        assert_eq!(t.claims.budget_id, bid);
        assert_eq!(t.claims.expiration, exp);

        let verified_claims = t.verify(pub_key.as_bytes()).unwrap();

        assert_eq!(verified_claims.invite_id, iid);
        assert_eq!(verified_claims.key_id, kid);
        assert_eq!(verified_claims.budget_id, bid);
        assert_eq!(verified_claims.expiration, exp);

        let mut token = format!("{claims}|{signature}");

        // Make the signature invalid
        let last_char = token.pop().unwrap();
        if last_char == 'a' {
            token.push('b');
        } else {
            token.push('a');
        }

        let token = b64_urlsafe.encode(&token);
        assert!(BudgetAcceptToken::decode(&token)
            .unwrap()
            .verify(pub_key.as_bytes())
            .is_err());

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = BudgetAcceptTokenClaims {
            invite_id: iid,
            key_id: kid,
            budget_id: bid,
            expiration: exp,
        };
        let claims = serde_json::to_vec(&claims).unwrap();
        let claims = String::from_utf8_lossy(&claims);

        let signature = hex::encode(keypair.sign(claims.as_bytes()).to_bytes());

        let token = b64_urlsafe.encode(format!("{claims}|{signature}"));
        assert!(BudgetAcceptToken::decode(&token)
            .unwrap()
            .verify(pub_key.as_bytes())
            .is_err());
    }
}
