use aes_gcm::{aead::Aead, Aes128Gcm};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TokenClaims {
    pub exp: u64,    // Expiration in time since UNIX epoch
    pub uid: Uuid,   // User ID (gets encrypted)
    pub eml: String, // User email address (gets encrypted)
    pub typ: u8,     // Token type (Access=0, Refresh=1, SignIn=2)
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct PrivateTokenClaims {
    pub uid: Uuid,
    pub eml: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct NewPrivateTokenClaims<'a> {
    pub uid: Uuid,
    pub eml: &'a str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct DecodedToken {
    pub exp: u64,

    // uid and eml get encrypted
    pub nnc: String, // Nonce for encryption (base64 encoded)
    pub enc: String, // Encrypted fields (base64 encoded)

    pub typ: u8,
}

impl TokenClaims {
    pub fn create_token(&self, signing_key: &[u8; 64], cipher: &Aes128Gcm) -> String {
        let private_claims = NewPrivateTokenClaims {
            uid: self.uid,
            eml: &self.eml,
        };

        let private_claims_json = serde_json::to_vec(&private_claims)
            .expect("Failed to transform private claims into JSON");

        let nonce: [u8; 12] = OsRng.gen();

        let encrypted_private_claims = cipher
            .encrypt((&nonce).into(), private_claims_json.as_ref())
            .expect("Failed to encrypt private token claims");

        let unencoded_token = DecodedToken {
            exp: self.exp,

            nnc: base64::encode(nonce),
            enc: base64::encode(encrypted_private_claims),

            typ: self.typ,
        };

        let mut claims_and_hash =
            serde_json::to_vec(&unencoded_token).expect("Failed to transform claims into JSON");

        let mut mac = HmacSha256::new(signing_key.into());
        mac.update(&claims_and_hash);
        let hash = hex::encode(mac.finalize().into_bytes());

        claims_and_hash.push(124); // 124 is the ASCII value of the | character
        claims_and_hash.extend_from_slice(&hash.into_bytes());

        base64::encode_config(claims_and_hash, base64::URL_SAFE_NO_PAD)
    }

    pub fn from_token_with_validation(
        token: &str,
        signing_key: &[u8; 64],
        cipher: &Aes128Gcm,
    ) -> Result<TokenClaims, TokenError> {
        let (claims, claims_json_str, hash) = TokenClaims::token_to_claims_and_hash(token, cipher)?;

        let time_since_epoch = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(t) => t,
            Err(_) => return Err(TokenError::SystemResourceAccessFailure),
        };

        if time_since_epoch.as_secs() >= claims.exp {
            return Err(TokenError::TokenExpired);
        }

        let mut mac = HmacSha256::new(signing_key.into());
        mac.update(claims_json_str.as_bytes());

        let correct_hash = mac.finalize().into_bytes();

        let mut hashes_dont_match = 0u8;

        if correct_hash.len() != hash.len() || hash.is_empty() {
            return Err(TokenError::TokenInvalid);
        }

        // Do bitwise comparison to prevent timing attacks
        for (i, correct_hash_byte) in correct_hash.iter().enumerate() {
            hashes_dont_match |= correct_hash_byte ^ hash[i];
        }

        if hashes_dont_match == 0 {
            Ok(claims)
        } else {
            Err(TokenError::TokenInvalid)
        }
    }

    pub fn from_token_without_validation(
        token: &str,
        cipher: &Aes128Gcm,
    ) -> Result<TokenClaims, TokenError> {
        Ok(TokenClaims::token_to_claims_and_hash(token, cipher)?.0)
    }

    fn token_to_claims_and_hash(
        token: &str,
        cipher: &Aes128Gcm,
    ) -> Result<(TokenClaims, String, Vec<u8>), TokenError> {
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

        let encrypted_claims_json_str = split_token.collect::<String>();
        let encrypted_claims =
            match serde_json::from_str::<DecodedToken>(&encrypted_claims_json_str) {
                Ok(c) => c,
                Err(_) => return Err(TokenError::TokenInvalid),
            };

        let nonce = match base64::decode(encrypted_claims.nnc) {
            Ok(n) => n,
            Err(_) => return Err(TokenError::TokenInvalid),
        };

        let private_claims = match base64::decode(encrypted_claims.enc) {
            Ok(c) => c,
            Err(_) => return Err(TokenError::TokenInvalid),
        };

        let decrypted_claims_bytes = match cipher.decrypt((&*nonce).into(), private_claims.as_ref())
        {
            Ok(c) => c,
            Err(_) => return Err(TokenError::TokenInvalid),
        };

        let decrypted_claims_json_str = match String::from_utf8(decrypted_claims_bytes) {
            Ok(s) => s,
            Err(_) => return Err(TokenError::TokenInvalid),
        };

        let decrypted_claims =
            match serde_json::from_str::<PrivateTokenClaims>(&decrypted_claims_json_str) {
                Ok(c) => c,
                Err(_) => return Err(TokenError::TokenInvalid),
            };

        let claims = TokenClaims {
            exp: encrypted_claims.exp,
            uid: decrypted_claims.uid,
            eml: decrypted_claims.eml,
            typ: encrypted_claims.typ,
        };

        Ok((claims, encrypted_claims_json_str, hash))
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
pub fn generate_token_pair(
    params: &TokenParams,
    access_token_lifetime: Duration,
    refresh_token_lifetime: Duration,
    signing_key: &[u8; 64],
    cipher: &Aes128Gcm,
) -> Result<TokenPair, TokenError> {
    let access_token = generate_token(
        params,
        TokenType::Access,
        access_token_lifetime,
        signing_key,
        cipher,
    )?;
    let refresh_token = generate_token(
        params,
        TokenType::Refresh,
        refresh_token_lifetime,
        signing_key,
        cipher,
    )?;

    Ok(TokenPair {
        access_token,
        refresh_token,
    })
}

pub fn generate_token(
    params: &TokenParams,
    kind: TokenType,
    lifetime: Duration,
    signing_key: &[u8; 64],
    cipher: &Aes128Gcm,
) -> Result<Token, TokenError> {
    let time_since_epoch = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(t) => t,
        Err(_) => return Err(TokenError::SystemResourceAccessFailure),
    };

    let expiration = (time_since_epoch + lifetime).as_secs();

    let claims = TokenClaims {
        exp: expiration,
        uid: params.user_id,
        eml: params.user_email.to_string(),
        typ: kind.into(),
    };

    let token = claims.create_token(signing_key, cipher);

    Ok(Token {
        token,
        token_type: kind,
    })
}

pub fn validate_token(
    token: &str,
    kind: TokenType,
    signing_key: &[u8; 64],
    cipher: &Aes128Gcm,
) -> Result<TokenClaims, TokenError> {
    let decoded_token = TokenClaims::from_token_with_validation(token, signing_key, cipher)?;

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

    use aes_gcm::{
        aead::{KeyInit, OsRng},
        Aes128Gcm,
    };

    #[test]
    fn test_claims_from_token_with_validation() {
        let claims = TokenClaims {
            exp: u64::MAX,
            uid: Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
            eml: "Testing_tokens@example.com".to_string(),
            typ: u8::from(TokenType::Access),
        };

        let cipher = Aes128Gcm::new(&Aes128Gcm::generate_key(&mut OsRng));
        let token = claims.create_token(&[0u8; 64], &cipher);
        let result = TokenClaims::from_token_with_validation(&token, &[0u8; 64], &cipher);

        assert!(result.is_ok());

        let decoded_claims = result.unwrap();

        assert_eq!(decoded_claims.exp, claims.exp);
        assert_eq!(decoded_claims.uid, claims.uid);
        assert_eq!(decoded_claims.eml, claims.eml);
        assert_eq!(decoded_claims.typ, claims.typ);
    }

    #[test]
    fn test_token_validation_fails_with_wrong_key() {
        let claims = TokenClaims {
            exp: u64::MAX,
            uid: Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
            eml: "Testing_tokens@example.com".to_string(),
            typ: u8::from(TokenType::Access),
        };

        let cipher = Aes128Gcm::new(&Aes128Gcm::generate_key(&mut OsRng));
        let token = claims.create_token(&[0u8; 64], &cipher);
        let result = TokenClaims::from_token_with_validation(&token, &[1u8; 64], &cipher);

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
        };

        let cipher = Aes128Gcm::new(&Aes128Gcm::generate_key(&mut OsRng));
        let token = claims.create_token(&[0u8; 64], &cipher);
        let result = TokenClaims::from_token_with_validation(&token, &[0u8; 64], &cipher);

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
        };

        let cipher = Aes128Gcm::new(&Aes128Gcm::generate_key(&mut OsRng));
        let token = claims.create_token(&[0u8; 64], &cipher);
        let decoded_claims = TokenClaims::from_token_without_validation(&token, &cipher).unwrap();

        assert_eq!(decoded_claims.exp, claims.exp);
        assert_eq!(decoded_claims.uid, claims.uid);
        assert_eq!(decoded_claims.eml, claims.eml);
        assert_eq!(decoded_claims.typ, claims.typ);
    }
}
