use crate::token::{Ed25519Verifier, Expiring, Token};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct BudgetInviteSenderTokenClaims {
    pub invite_id: Uuid,
    pub expiration: u64,
}

impl Expiring for BudgetInviteSenderTokenClaims {
    fn expiration(&self) -> u64 {
        self.expiration
    }
}

pub struct BudgetInviteSenderToken {}

impl Token for BudgetInviteSenderToken {
    type Claims = BudgetInviteSenderTokenClaims;
    type Verifier = Ed25519Verifier;

    fn token_name() -> &'static str {
        "BudgetInviteSenderToken"
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
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = BudgetInviteSenderTokenClaims {
            invite_id: iid,
            expiration: exp,
        };
        let claims = serde_json::to_string(&claims).unwrap();

        let keypair = SigningKey::generate(&mut OsRng);
        let pub_key = keypair.verifying_key();
        let signature = hex::encode(keypair.sign(claims.as_bytes()).to_bytes());

        let token = b64_urlsafe.encode(format!("{claims}|{signature}"));
        let t = BudgetInviteSenderToken::decode(&token).unwrap();

        assert_eq!(t.claims.invite_id, iid);
        assert_eq!(t.claims.expiration, exp);

        let verified_claims = t.verify(pub_key.as_bytes()).unwrap();

        assert_eq!(verified_claims.invite_id, iid);
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
        assert!(BudgetInviteSenderToken::decode(&token)
            .unwrap()
            .verify(pub_key.as_bytes())
            .is_err());

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = BudgetInviteSenderTokenClaims {
            invite_id: iid,
            expiration: exp,
        };
        let claims = serde_json::to_string(&claims).unwrap();

        let signature = hex::encode(keypair.sign(claims.as_bytes()).to_bytes());

        let token = b64_urlsafe.encode(format!("{claims}|{signature}"));
        assert!(BudgetInviteSenderToken::decode(&token)
            .unwrap()
            .verify(pub_key.as_bytes())
            .is_err());
    }
}
