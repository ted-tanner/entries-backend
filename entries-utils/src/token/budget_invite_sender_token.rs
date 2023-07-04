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

    use ed25519_dalek::{Keypair, Signer};
    use old_rand::rngs::OsRng;
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
        let claims = serde_json::to_vec(&claims).unwrap();
        let claims = String::from_utf8_lossy(&claims);

        let keypair = Keypair::generate(&mut OsRng {});
        let pub_key = keypair.public.as_bytes();
        let signature = hex::encode(keypair.sign(claims.as_bytes()));

        let token = base64::encode_config(format!("{claims}|{signature}"), base64::URL_SAFE);
        let t = BudgetInviteSenderToken::decode(&token).unwrap();

        assert_eq!(t.claims.invite_id, iid);
        assert_eq!(t.claims.expiration, exp);

        let verified_claims = t.verify(&pub_key[..]).unwrap();

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

        let token = base64::encode_config(&token, base64::URL_SAFE);
        assert!(BudgetInviteSenderToken::decode(&token)
            .unwrap()
            .verify(&pub_key[..])
            .is_err());

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = BudgetInviteSenderTokenClaims {
            invite_id: iid,
            expiration: exp,
        };
        let claims = serde_json::to_vec(&claims).unwrap();
        let claims = String::from_utf8_lossy(&claims);

        let signature = hex::encode(keypair.sign(claims.as_bytes()));

        let token = base64::encode_config(format!("{claims}|{signature}"), base64::URL_SAFE);
        assert!(BudgetInviteSenderToken::decode(&token)
            .unwrap()
            .verify(&pub_key[..])
            .is_err());
    }
}
