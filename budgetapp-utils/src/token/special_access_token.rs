use crate::token::{ClientSignedToken, TokenParts, Ed25519Verifier};

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
    parts: TokenParts,
}

impl<'a> ClientSignedToken<'a> for SpecialAccessToken {
    type Claims = SpecialAccessTokenClaims;
    type InternalClaims = SpecialAccessTokenInternalClaims;
    type Verifier = Ed25519Verifier;

    fn from_pieces(claims: Self::InternalClaims, parts: TokenParts) -> Self {
        Self { claims, parts }
    }

    fn user_id(&self) -> Uuid { self.claims.uid }
    fn expiration(&self) -> u64 { self.claims.exp }

    fn claims(&self) -> Self::Claims {
        SpecialAccessTokenClaims {
            key_id: self.claims.kid,
            budget_id: self.claims.bid,
            user_id: self.claims.uid,
            expiration: self.claims.exp,
        }
    }

    fn json(&'a self) -> &'a str { &self.parts.json }
    fn signature(&'a self) -> &'a [u8] { &self.parts.signature }
}
