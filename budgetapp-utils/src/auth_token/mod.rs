use hmac::{Hmac, Mac};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug)]
pub enum TokenError {
    InvalidTokenType(TokenTypeError),
    TokenInvalid,
    TokenExpired,
    SystemResourceAccessFailure,
    WrongTokenType,
}

impl std::error::Error for TokenError {}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::InvalidTokenType(e) => write!(f, "InvalidTokenType: {e}"),
            TokenError::TokenInvalid => write!(f, "TokenInvalid"),
            TokenError::TokenExpired => write!(f, "TokenExpired"),
            TokenError::SystemResourceAccessFailure => write!(f, "SystemResourceAccessFailure"),
            TokenError::WrongTokenType => write!(f, "WrongTokenType"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TokenType {
    Access,
    Refresh,
    SignIn,
    UserCreation,
    UserDeletion,
}

#[derive(Debug)]
pub enum TokenTypeError {
    NoMatchForValue(u8),
}

impl std::error::Error for TokenTypeError {}

impl fmt::Display for TokenTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenTypeError::NoMatchForValue(v) => write!(f, "NoMatchForValue: {v}"),
        }
    }
}

impl std::convert::TryFrom<u8> for TokenType {
    type Error = TokenTypeError;

    fn try_from(value: u8) -> Result<Self, TokenTypeError> {
        match value {
            0 => Ok(TokenType::Access),
            1 => Ok(TokenType::Refresh),
            2 => Ok(TokenType::SignIn),
            3 => Ok(TokenType::UserCreation),
            4 => Ok(TokenType::UserDeletion),
            v => Err(TokenTypeError::NoMatchForValue(v)),
        }
    }
}

impl std::convert::From<TokenType> for u8 {
    fn from(token_type: TokenType) -> Self {
        match token_type {
            TokenType::Access => 0,
            TokenType::Refresh => 1,
            TokenType::SignIn => 2,
            TokenType::UserCreation => 3,
            TokenType::UserDeletion => 4,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenParams<'a> {
    pub user_id: Uuid,
    pub user_email: &'a str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenClaims {
    pub exp: u64,    // Expiration in time since UNIX epoch
    pub uid: Uuid,   // User ID
    pub eml: String, // User email address
    pub typ: u8,     // Token type (Access=0, Refresh=1, SignIn=2)
    pub slt: u32,    // Random salt (makes it so two tokens generated in the same
                     // second are different--useful for preventing replay attacks
                     // while allowing new tokens to be generated for the client)
}

impl TokenClaims {
    pub fn create_token(&self, key: &[u8]) -> String {
        let mut claims_and_hash =
            serde_json::to_vec(self).expect("Failed to transform claims into JSON");

        let mut mac =
            Hmac::<Sha256>::new_from_slice(key).expect("Failed to generate hash from key");
        mac.update(&claims_and_hash);
        let hash = hex::encode(mac.finalize().into_bytes());

        claims_and_hash.push(124); // 124 is the ASCII value of the | character
        claims_and_hash.extend_from_slice(&hash.into_bytes());

        base64::encode_config(claims_and_hash, base64::URL_SAFE_NO_PAD)
    }

    pub fn from_token_with_validation(token: &str, key: &[u8]) -> Result<TokenClaims, TokenError> {
        let (claims, claims_json_str, hash) = TokenClaims::token_to_claims_and_hash(token)?;

        let time_since_epoch = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(t) => t,
            Err(_) => return Err(TokenError::SystemResourceAccessFailure),
        };

        if time_since_epoch.as_secs() >= claims.exp {
            return Err(TokenError::TokenExpired);
        }

        let mut mac =
            Hmac::<Sha256>::new_from_slice(key).expect("Failed to generate hash from key");
        mac.update(claims_json_str.as_bytes());

        match mac.verify_slice(&hash) {
            Ok(_) => Ok(claims),
            Err(_) => Err(TokenError::TokenInvalid),
        }
    }

    pub fn from_token_without_validation(token: &str) -> Result<TokenClaims, TokenError> {
        Ok(TokenClaims::token_to_claims_and_hash(token)?.0)
    }

    fn token_to_claims_and_hash(token: &str) -> Result<(TokenClaims, String, Vec<u8>), TokenError> {
        let decoded_token = match base64::decode_config(token.as_bytes(), base64::URL_SAFE_NO_PAD) {
            Ok(t) => t,
            Err(_) => return Err(TokenError::TokenInvalid),
        };

        let token_str = String::from_utf8_lossy(&decoded_token);
        let mut split_token = token_str.split('|');

        let hash_str = match split_token.next_back() {
            Some(h) => h,
            None => {
                return Err(TokenError::TokenInvalid);
            }
        };

        let hash = match hex::decode(hash_str) {
            Ok(h) => h,
            Err(_) => return Err(TokenError::TokenInvalid),
        };

        let claims_json_str = split_token.collect::<String>();
        let claims = match serde_json::from_str::<TokenClaims>(&claims_json_str) {
            Ok(c) => c,
            Err(_) => return Err(TokenError::TokenInvalid),
        };

        Ok((claims, claims_json_str, hash))
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Token {
    token: String,
    token_type: TokenType,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.token)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenPair {
    pub access_token: Token,
    pub refresh_token: Token,
}

#[inline]
pub fn generate_access_token(
    params: &TokenParams,
    lifetime: Duration,
    signing_key: &[u8],
) -> Result<Token, TokenError> {
    generate_token(params, TokenType::Access, lifetime, signing_key)
}

#[inline]
pub fn generate_refresh_token(
    params: &TokenParams,
    lifetime: Duration,
    signing_key: &[u8],
) -> Result<Token, TokenError> {
    generate_token(params, TokenType::Refresh, lifetime, signing_key)
}

#[inline]
pub fn generate_signin_token(
    params: &TokenParams,
    lifetime: Duration,
    signing_key: &[u8],
) -> Result<Token, TokenError> {
    generate_token(params, TokenType::SignIn, lifetime, signing_key)
}

#[inline]
pub fn generate_user_creation_token(
    params: &TokenParams,
    lifetime: Duration,
    signing_key: &[u8],
) -> Result<Token, TokenError> {
    generate_token(params, TokenType::UserCreation, lifetime, signing_key)
}

#[inline]
pub fn generate_user_deletion_token(
    params: &TokenParams,
    lifetime: Duration,
    signing_key: &[u8],
) -> Result<Token, TokenError> {
    generate_token(params, TokenType::UserDeletion, lifetime, signing_key)
}

#[inline]
pub fn generate_token_pair(
    params: &TokenParams,
    access_token_lifetime: Duration,
    refresh_token_lifetime: Duration,
    signing_key: &[u8],
) -> Result<TokenPair, TokenError> {
    let access_token = generate_access_token(params, access_token_lifetime, signing_key)?;
    let refresh_token = generate_refresh_token(params, refresh_token_lifetime, signing_key)?;

    Ok(TokenPair {
        access_token,
        refresh_token,
    })
}

fn generate_token(
    params: &TokenParams,
    kind: TokenType,
    lifetime: Duration,
    signing_key: &[u8],
) -> Result<Token, TokenError> {
    let time_since_epoch = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(t) => t,
        Err(_) => return Err(TokenError::SystemResourceAccessFailure),
    };

    let expiration = (time_since_epoch + lifetime).as_secs();
    let salt = rand::thread_rng().gen_range(1..u32::MAX);

    let claims = TokenClaims {
        exp: expiration,
        uid: params.user_id,
        eml: params.user_email.to_string(),
        typ: kind.into(),
        slt: salt,
    };

    let token = claims.create_token(signing_key);

    Ok(Token {
        token,
        token_type: kind,
    })
}

#[inline]
pub fn validate_access_token(token: &str, signing_key: &[u8]) -> Result<TokenClaims, TokenError> {
    validate_token(token, TokenType::Access, signing_key)
}

#[inline]
pub fn validate_refresh_token(token: &str, signing_key: &[u8]) -> Result<TokenClaims, TokenError> {
    validate_token(token, TokenType::Refresh, signing_key)
}

#[inline]
pub fn validate_signin_token(token: &str, signing_key: &[u8]) -> Result<TokenClaims, TokenError> {
    validate_token(token, TokenType::SignIn, signing_key)
}

#[inline]
pub fn validate_user_creation_token(
    token: &str,
    signing_key: &[u8],
) -> Result<TokenClaims, TokenError> {
    validate_token(token, TokenType::UserCreation, signing_key)
}

#[inline]
pub fn validate_user_deletion_token(
    token: &str,
    signing_key: &[u8],
) -> Result<TokenClaims, TokenError> {
    validate_token(token, TokenType::UserDeletion, signing_key)
}

fn validate_token(
    token: &str,
    kind: TokenType,
    signing_key: &[u8],
) -> Result<TokenClaims, TokenError> {
    let decoded_token = TokenClaims::from_token_with_validation(token, signing_key)?;

    let token_type_claim = match TokenType::try_from(decoded_token.typ) {
        Ok(t) => t,
        Err(e) => return Err(TokenError::InvalidTokenType(e)),
    };

    if token_type_claim != kind {
        Err(TokenError::WrongTokenType)
    } else {
        Ok(decoded_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_token() {
        let claims = TokenClaims {
            exp: 123456789,
            uid: Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
            eml: "Testing_tokens@example.com".to_string(),
            typ: u8::from(TokenType::Access),
            slt: 10000,
        };

        let token = claims.create_token("thisIsAFakeKey".as_bytes());

        let decoded_token =
            base64::decode_config(token.as_bytes(), base64::URL_SAFE_NO_PAD).unwrap();
        let token_str = String::from_utf8_lossy(&decoded_token);
        let mut split_token = token_str.split('|');
        split_token.next_back();

        let claims_json_str = split_token.collect::<String>();
        let decoded_claims = serde_json::from_str::<TokenClaims>(claims_json_str.as_str()).unwrap();

        assert_eq!(decoded_claims.exp, claims.exp);
        assert_eq!(decoded_claims.uid, claims.uid);
        assert_eq!(decoded_claims.eml, claims.eml);
        assert_eq!(decoded_claims.typ, claims.typ);
        assert_eq!(decoded_claims.slt, claims.slt);
    }

    #[test]
    fn test_claims_from_token_with_validation() {
        let claims = TokenClaims {
            exp: u64::MAX,
            uid: Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
            eml: "Testing_tokens@example.com".to_string(),
            typ: u8::from(TokenType::Access),
            slt: 10000,
        };

        let token = claims.create_token(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let result = TokenClaims::from_token_with_validation(
            &token,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        );

        assert!(result.is_ok());

        let decoded_claims = result.unwrap();

        assert_eq!(decoded_claims.exp, claims.exp);
        assert_eq!(decoded_claims.uid, claims.uid);
        assert_eq!(decoded_claims.eml, claims.eml);
        assert_eq!(decoded_claims.typ, claims.typ);
        assert_eq!(decoded_claims.slt, claims.slt);
    }

    #[test]
    fn test_token_validation_fails_with_wrong_key() {
        let claims = TokenClaims {
            exp: u64::MAX,
            uid: Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
            eml: "Testing_tokens@example.com".to_string(),
            typ: u8::from(TokenType::Access),
            slt: 10000,
        };

        let token = claims.create_token(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let result = TokenClaims::from_token_with_validation(
            &token,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17],
        );

        let error = result.unwrap_err();

        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&TokenError::TokenInvalid)
        );
    }

    #[test]
    fn test_token_validation_fails_when_expired() {
        let claims = TokenClaims {
            exp: 1657076995,
            uid: Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
            eml: "Testing_tokens@example.com".to_string(),
            typ: u8::from(TokenType::Access),
            slt: 10000,
        };

        let token = claims.create_token(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let result = TokenClaims::from_token_with_validation(
            &token,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        );

        let error = result.unwrap_err();

        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&TokenError::TokenExpired)
        );
    }

    #[test]
    fn test_claims_from_token_without_validation() {
        let claims = TokenClaims {
            exp: 1657076995,
            uid: Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
            eml: "Testing_tokens@example.com".to_string(),
            typ: u8::from(TokenType::Access),
            slt: 10000,
        };

        let token = claims.create_token(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let decoded_claims = TokenClaims::from_token_without_validation(&token).unwrap();

        assert_eq!(decoded_claims.exp, claims.exp);
        assert_eq!(decoded_claims.uid, claims.uid);
        assert_eq!(decoded_claims.eml, claims.eml);
        assert_eq!(decoded_claims.typ, claims.typ);
        assert_eq!(decoded_claims.slt, claims.slt);
    }
}
