use crate::token::{Ed25519Verifier, Token, TokenParts};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct BudgetAcceptTokenClaims {
    pub invitation_id: Uuid,
    pub key_id: Uuid,
    pub budget_id: Uuid,
    pub expiration: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BudgetAcceptTokenInternalClaims {
    iid: Uuid, // Invitation ID
    kid: Uuid, // Budget Share Key ID
    bid: Uuid, // Budget ID
    exp: u64,  // Expiration
}

pub struct BudgetAcceptToken {
    claims: BudgetAcceptTokenInternalClaims,
    parts: Option<TokenParts>,
}

impl BudgetAcceptToken {
    pub fn key_id(&self) -> Uuid {
        self.claims.kid
    }

    pub fn budget_id(&self) -> Uuid {
        self.claims.bid
    }
}

impl<'a> Token<'a> for BudgetAcceptToken {
    type Claims = BudgetAcceptTokenClaims;
    type InternalClaims = BudgetAcceptTokenInternalClaims;
    type Verifier = Ed25519Verifier;

    fn token_name() -> &'static str {
        "BudgetAcceptToken"
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
        BudgetAcceptTokenClaims {
            invitation_id: self.claims.iid,
            kid_id: self.claims.kid,
            budget_id: self.claims.bid,
            expiration: self.claims.exp,
        }
    }
}
