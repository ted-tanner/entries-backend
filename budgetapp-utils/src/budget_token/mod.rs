use ed25519_dalek::{PublicKey, Signature, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub struct BudgetToken {
    pub key_id: Uuid,
    pub budget_id: Uuid,
    pub user_id: Uuid,
    pub expiration: u64,
    pub json: String,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub enum BudgetTokenError {
    TokenInvalid,
}

impl std::error::Error for BudgetTokenError {}

impl fmt::Display for BudgetTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BudgetTokenError::TokenInvalid => write!(f, "TokenInvalid"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct BudgetTokenClaims {
    kid: Uuid, // Key ID
    bid: Uuid, // Budget ID
    uid: Uuid, // User ID
    exp: u64,  // Expiration
}

impl BudgetToken {
    pub fn from_str(token: &str) -> Result<Self, BudgetTokenError> {
        let decoded_token = match base64::decode_config(token.as_bytes(), base64::URL_SAFE_NO_PAD) {
            Ok(t) => t,
            Err(_) => return Err(BudgetTokenError::TokenInvalid),
        };

        let token_str = String::from_utf8_lossy(&decoded_token);
        let mut split_token = token_str.split('|');

        let signature_str = match split_token.next_back() {
            Some(h) => h,
            None => return Err(BudgetTokenError::TokenInvalid),
        };

        let signature = match hex::decode(signature_str) {
            Ok(h) => h,
            Err(_) => return Err(BudgetTokenError::TokenInvalid),
        };

        let claims_json_str = split_token.collect::<String>();
        let claims = match serde_json::from_str::<BudgetTokenClaims>(&claims_json_str) {
            Ok(c) => c,
            Err(_) => return Err(BudgetTokenError::TokenInvalid),
        };

        Ok(Self {
            key_id: claims.kid,
            budget_id: claims.bid,
            user_id: claims.uid,
            expiration: claims.exp,
            json: claims_json_str,
            signature,
        })
    }

    pub fn verify_for_user(&self, expected_user_id: Uuid, public_key: &[u8]) -> bool {
        if self.user_id != expected_user_id {
            return false;
        }

        if self.expiration
            >= SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        {
            return false;
        }

        if self.signature.len() != SIGNATURE_LENGTH {
            return false;
        }

        if public_key.len() != PUBLIC_KEY_LENGTH {
            return false;
        }

        let public_key = match PublicKey::from_bytes(public_key) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let signature = match Signature::from_bytes(&self.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        match public_key.verify_strict(self.json.as_bytes(), &signature) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}
