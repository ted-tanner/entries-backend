use crate::token::{Ed25519Verifier, Token, TokenParts};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct BudgetAccessTokenClaims {
    pub key_id: Uuid,
    pub budget_id: Uuid,
    pub user_email: String,
    pub expiration: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BudgetAccessTokenInternalClaims {
    kid: Uuid,   // Key ID
    bid: Uuid,   // Budget ID
    eml: String, // User ID
    exp: u64,    // Expiration
}

pub struct BudgetAccessToken {
    claims: BudgetAccessTokenInternalClaims,
    parts: Option<TokenParts>,
}

impl<'a> Token<'a> for BudgetAccessToken {
    type Claims = BudgetAccessTokenClaims;
    type InternalClaims = BudgetAccessTokenInternalClaims;
    type Verifier = Ed25519Verifier;

    fn clear_buffers(&mut self) {
        self.parts = None;
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
            user_email: self.claims.eml,
            expiration: self.claims.exp,
        }
    }
}
