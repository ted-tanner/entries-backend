use crate::token::{Ed25519Verifier, Expiring, Token};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct BudgetAccessTokenClaims {
    pub kid: Uuid, // Key ID
    pub bid: Uuid, // Budget ID
    pub exp: u64,  // Expiration
}

impl Expiring for BudgetAccessTokenClaims {
    fn expiration(&self) -> u64 {
        self.exp
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

    use ed25519_dalek::{Keypair, Signer};
    use old_rand::rngs::OsRng;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn test_verify() {
        let kid = Uuid::new_v4();
        let bid = Uuid::new_v4();
        let exp = (SystemTime::now() + Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = BudgetAccessTokenClaims { kid, bid, exp };
        let claims = serde_json::to_vec(&claims).unwrap();
        let claims = String::from_utf8_lossy(&claims);

        let keypair = Keypair::generate(&mut OsRng {});
        let pub_key = keypair.public.as_bytes();
        let signature = hex::encode(keypair.sign(claims.as_bytes()));

        let token = base64::encode_config(format!("{claims}|{signature}"), base64::URL_SAFE);
        let verified_claims = BudgetAccessToken::decode(&token)
            .unwrap()
            .verify(&pub_key[..])
            .unwrap();

        assert_eq!(verified_claims.kid, kid);
        assert_eq!(verified_claims.bid, bid);
        assert_eq!(verified_claims.exp, exp);

        let mut token = format!("{claims}|{signature}");

        // Make the signature invalid
        let last_char = token.pop().unwrap();
        if last_char == 'a' {
            token.push('b');
        } else {
            token.push('a');
        }

        let token = base64::encode_config(&token, base64::URL_SAFE);
        assert!(BudgetAccessToken::decode(&token)
            .unwrap()
            .verify(&pub_key[..])
            .is_err());

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = BudgetAccessTokenClaims { kid, bid, exp };
        let claims = serde_json::to_vec(&claims).unwrap();
        let claims = String::from_utf8_lossy(&claims);

        let signature = hex::encode(keypair.sign(claims.as_bytes()));

        let token = base64::encode_config(format!("{claims}|{signature}"), base64::URL_SAFE);
        assert!(BudgetAccessToken::decode(&token)
            .unwrap()
            .verify(&pub_key[..])
            .is_err());
    }
}
