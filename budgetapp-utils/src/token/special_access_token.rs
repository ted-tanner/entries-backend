use crate::token::{Ed25519Verifier, TokenParts, UserToken};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct SpecialAccessTokenClaims {
    pub key_id: Uuid,
    pub budget_id: Uuid,
    pub user_id: Uuid,
    pub expiration: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SpecialAccessTokenInternalClaims {
    kid: Uuid, // Key ID
    bid: Uuid, // Budget ID
    uid: Uuid, // User ID
    exp: u64,  // Expiration
}

pub struct SpecialAccessToken {
    claims: SpecialAccessTokenInternalClaims,
    parts: Option<TokenParts>,
}

impl<'a> UserToken<'a> for SpecialAccessToken {
    type Claims = SpecialAccessTokenClaims;
    type InternalClaims = SpecialAccessTokenInternalClaims;
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
        SpecialAccessTokenClaims {
            key_id: self.claims.kid,
            budget_id: self.claims.bid,
            user_id: self.claims.uid,
            expiration: self.claims.exp,
        }
    }
}
