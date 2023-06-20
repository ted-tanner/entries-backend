use crate::token::{Ed25519Verifier, Token, TokenParts};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct BudgetAccessTokenClaims {
    pub key_id: Uuid,
    pub budget_id: Uuid,
    pub expiration: u64,
}

#[repr(C)]
#[derive(Debug, Serialize, Deserialize)]
pub struct BudgetAccessTokenInternalClaims {
    pub kid: Uuid, // Key ID
    pub bid: Uuid, // Budget ID
    pub exp: u64,  // Expiration
}

pub struct BudgetAccessToken {
    claims: BudgetAccessTokenInternalClaims,
    parts: Option<TokenParts>,
}

impl BudgetAccessToken {
    pub fn key_id(&self) -> Uuid {
        self.claims.kid
    }

    pub fn budget_id(&self) -> Uuid {
        self.claims.bid
    }
}

impl<'a> Token<'a> for BudgetAccessToken {
    type Claims = BudgetAccessTokenClaims;
    type InternalClaims = BudgetAccessTokenInternalClaims;
    type Verifier = Ed25519Verifier;

    fn token_name() -> &'static str {
        "BudgetAccessToken"
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
        BudgetAccessTokenClaims {
            key_id: self.claims.kid,
            budget_id: self.claims.bid,
            expiration: self.claims.exp,
        }
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

        let claims = BudgetAccessTokenInternalClaims { kid, bid, exp };
        let claims = serde_json::to_vec(&claims).unwrap();

        let keypair = Keypair::generate(&mut OsRng {});
        let pub_key = keypair.public.as_bytes();
        let signature = hex::encode(keypair.sign(&claims));

        let claims = String::from_utf8_lossy(&claims);
        let token = base64::encode_config(format!("{claims}|{signature}"), base64::URL_SAFE_NO_PAD);

        let token = BudgetAccessToken::from_str(&token).unwrap();
        assert!(token.verify(pub_key));

        let mut token = format!("{claims}|{signature}");

        // Make the signature invalid
        let last_char = token.pop().unwrap();
        if last_char == 'a' {
            token.push('b');
        } else {
            token.push('a');
        }

        let token = base64::encode_config(&token, base64::URL_SAFE_NO_PAD);

        let token = BudgetAccessToken::from_str(&token).unwrap();
        assert!(!token.verify(pub_key));

        let exp = (SystemTime::now() - Duration::from_secs(10))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = BudgetAccessTokenInternalClaims { kid, bid, exp };
        let claims = serde_json::to_vec(&claims).unwrap();
        let claims = String::from_utf8_lossy(&claims);

        let signature = hex::encode(keypair.sign(claims.as_bytes()));

        let token = base64::encode_config(format!("{claims}|{signature}"), base64::URL_SAFE_NO_PAD);

        let token = BudgetAccessToken::from_str(&token).unwrap();
        assert!(!token.verify(pub_key));
    }
}
