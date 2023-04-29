use crate::token::{Ed25519Verifier, Token, TokenParts};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct BudgetInviteSenderTokenClaims {
    pub invitation_id: Uuid,
    pub expiration: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BudgetInviteSenderTokenInternalClaims {
    iid: Uuid, // Invitation ID
    exp: u64,  // Expiration
}

pub struct BudgetInviteSenderToken {
    claims: BudgetInviteSenderTokenInternalClaims,
    parts: Option<TokenParts>,
}

impl BudgetInviteSenderToken {
    pub fn invitation_id(&self) -> Uuid {
        self.claims.iid
    }
}

impl<'a> Token<'a> for BudgetInviteSenderToken {
    type Claims = BudgetInviteSenderTokenClaims;
    type InternalClaims = BudgetInviteSenderTokenInternalClaims;
    type Verifier = Ed25519Verifier;

    fn token_name() -> &'static str {
        "BudgetInviteSenderToken"
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
        BudgetInviteSenderTokenClaims {
            invitation_id: self.claims.iid,
            expiration: self.claims.exp,
        }
    }
}
