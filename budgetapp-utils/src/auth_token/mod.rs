use hmac::{Hmac, Mac};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::db::auth::Dao as AuthDao;
use crate::db::DaoError;

#[derive(Debug)]
pub enum TokenError {
    DatabaseError(DaoError),
    InvalidTokenType(TokenTypeError),
    TokenInvalid,
    TokenBlacklisted,
    TokenExpired,
    SystemResourceAccessFailure,
    WrongTokenType,
}

impl std::error::Error for TokenError {}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::DatabaseError(e) => write!(f, "DatabaseError: {}", e),
            TokenError::InvalidTokenType(e) => write!(f, "InvalidTokenType: {}", e),
            _ => write!(f, "Unknown TokenError"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TokenType {
    Access,
    Refresh,
    SignIn,
}

#[derive(Debug)]
pub enum TokenTypeError {
    NoMatchForValue(u8),
}

impl std::error::Error for TokenTypeError {}

impl fmt::Display for TokenTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenTypeError::NoMatchForValue(v) => write!(f, "NoMatchForValue: {}", v),
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
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenParams<'a> {
    pub user_id: &'a Uuid,
    pub user_email: &'a str,
    pub user_currency: &'a str,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenClaims {
    pub exp: u64,    // Expiration in time since UNIX epoch
    pub uid: Uuid,   // User ID
    pub eml: String, // User email address
    pub cur: String, // User currency
    pub typ: u8,     // Token type (Access=0, Refresh=1, SignIn=2)
    pub slt: u32,    // Random salt (makes it so two tokens generated in the same
                     //              second are different--useful for testing)
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

#[derive(Debug, Serialize, Deserialize)]
pub struct InputBlacklistedRefreshToken {
    pub token: String,
    pub token_expiration_epoch: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Token {
    token: String,
    token_type: TokenType,
}

impl Token {
    #[allow(dead_code)]
    fn is_access_token(&self) -> bool {
        matches!(self.token_type, TokenType::Access)
    }

    #[allow(dead_code)]
    fn is_refresh_token(&self) -> bool {
        matches!(self.token_type, TokenType::Refresh)
    }

    #[allow(dead_code)]
    fn is_signin_token(&self) -> bool {
        matches!(self.token_type, TokenType::SignIn)
    }
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
        uid: *params.user_id,
        eml: params.user_email.to_string(),
        cur: params.user_currency.to_string(),
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
pub fn validate_refresh_token(
    token: &str,
    signing_key: &[u8],
    auth_dao: &mut AuthDao,
) -> Result<TokenClaims, TokenError> {
    if is_on_blacklist(token, auth_dao)? {
        return Err(TokenError::TokenBlacklisted);
    }

    validate_token(token, TokenType::Refresh, signing_key)
}

#[inline]
pub fn validate_signin_token(token: &str, signing_key: &[u8]) -> Result<TokenClaims, TokenError> {
    validate_token(token, TokenType::SignIn, signing_key)
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

pub fn blacklist_token(token: &str, dao: &mut AuthDao) -> Result<(), TokenError> {
    let decoded_token = TokenClaims::from_token_without_validation(token)?;

    let user_id = decoded_token.uid;
    let expiration = UNIX_EPOCH
        + Duration::from_secs(match i64::try_from(decoded_token.exp) {
            Ok(exp) => exp,
            Err(_) => return Err(TokenError::TokenInvalid),
        } as u64);

    match dao.create_blacklisted_token(token, user_id, expiration) {
        Ok(_) => Ok(()),
        Err(e) => Err(TokenError::DatabaseError(e)),
    }
}

#[inline]
pub fn is_on_blacklist(token: &str, dao: &mut AuthDao) -> Result<bool, TokenError> {
    match dao.check_is_token_on_blacklist(token) {
        Ok(o) => Ok(o),
        Err(e) => Err(TokenError::DatabaseError(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
    use std::time::SystemTime;

    use crate::models::blacklisted_token::BlacklistedToken;
    use crate::models::user::NewUser;
    use crate::schema::blacklisted_tokens as blacklisted_token_fields;
    use crate::schema::blacklisted_tokens::dsl::blacklisted_tokens;
    use crate::schema::users::dsl::users;
    use crate::test_env;

    #[test]
    fn test_create_token() {
        let claims = TokenClaims {
            exp: 123456789,
            uid: uuid::Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
            eml: "Testing_tokens@example.com".to_string(),
            cur: String::from("USD"),
            typ: u8::from(TokenType::Access),
            slt: 10000,
        };

        let claims_different = TokenClaims {
            exp: 123456788,
            uid: uuid::Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
            eml: "Testing_tokens@example.com".to_string(),
            cur: String::from("USD"),
            typ: u8::from(TokenType::Access),
            slt: 10000,
        };

        let token = claims.create_token("thisIsAFakeKey".as_bytes());
        let token_different = claims_different.create_token("thisIsAFakeKey".as_bytes());
        let expected_token = String::from("eyJleHAiOjEyMzQ1Njc4OSwidWlkIjoiNjdlNTUwNDQtMTBiMS00MjZmLTkyNDctYmI2ODBlNWZlMGM4IiwiZW1sIjoiVGVzdGluZ190b2tlbnNAZXhhbXBsZS5jb20iLCJjdXIiOiJVU0QiLCJ0eXAiOjAsInNsdCI6MTAwMDB9fGI2MTViNTcyZGEyYzUyODczMTliMTNiZmY1Yjg3YjE2MDU0NjNkNjM1NzBhMGE2M2M2ODFjNGM1ZDUyYTJhMzk");

        assert_eq!(token, expected_token);
        assert_ne!(token, token_different);

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
        assert_eq!(decoded_claims.cur, claims.cur);
        assert_eq!(decoded_claims.typ, claims.typ);
        assert_eq!(decoded_claims.slt, claims.slt);
    }

    #[test]
    fn test_claims_from_token_with_validation() {
        let claims = TokenClaims {
            exp: u64::MAX,
            uid: uuid::Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
            eml: "Testing_tokens@example.com".to_string(),
            cur: String::from("USD"),
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
        assert_eq!(decoded_claims.cur, claims.cur);
        assert_eq!(decoded_claims.typ, claims.typ);
        assert_eq!(decoded_claims.slt, claims.slt);
    }

    #[test]
    fn test_token_validation_fails_with_wrong_key() {
        let claims = TokenClaims {
            exp: u64::MAX,
            uid: uuid::Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
            eml: "Testing_tokens@example.com".to_string(),
            cur: String::from("USD"),
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
            uid: uuid::Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
            eml: "Testing_tokens@example.com".to_string(),
            cur: String::from("USD"),
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
            uid: uuid::Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
            eml: "Testing_tokens@example.com".to_string(),
            cur: String::from("USD"),
            typ: u8::from(TokenType::Access),
            slt: 10000,
        };

        let token = claims.create_token(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let decoded_claims = TokenClaims::from_token_without_validation(&token).unwrap();

        assert_eq!(decoded_claims.exp, claims.exp);
        assert_eq!(decoded_claims.uid, claims.uid);
        assert_eq!(decoded_claims.eml, claims.eml);
        assert_eq!(decoded_claims.cur, claims.cur);
        assert_eq!(decoded_claims.typ, claims.typ);
        assert_eq!(decoded_claims.slt, claims.slt);
    }

    #[test]
    fn test_generate_access_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let token = generate_access_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            "thisIsAFakeKey".as_bytes(),
        )
        .unwrap();

        assert!(!token.token.contains(&user_id.to_string()));

        let decoded_token =
            TokenClaims::from_token_with_validation(&token.token, "thisIsAFakeKey".as_bytes())
                .unwrap();

        assert_eq!(decoded_token.typ, u8::from(TokenType::Access));
        assert_eq!(decoded_token.uid, user_id);
        assert_eq!(decoded_token.eml, new_user.email);
        assert_eq!(decoded_token.cur, new_user.currency);
        assert!(
            decoded_token.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );
    }

    #[test]
    fn test_generate_refresh_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let token = generate_refresh_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            "thisIsAFakeKey".as_bytes(),
        )
        .unwrap();

        assert!(!token.token.contains(&user_id.to_string()));

        let decoded_token =
            TokenClaims::from_token_with_validation(&token.token, "thisIsAFakeKey".as_bytes())
                .unwrap();

        assert_eq!(decoded_token.typ, u8::from(TokenType::Refresh));
        assert_eq!(decoded_token.uid, user_id);
        assert_eq!(decoded_token.eml, new_user.email);
        assert_eq!(decoded_token.cur, new_user.currency);
        assert!(
            decoded_token.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );
    }

    #[test]
    fn test_generate_signin_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let token = generate_signin_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            "thisIsAFakeKey".as_bytes(),
        )
        .unwrap();

        assert!(!token.token.contains(&user_id.to_string()));

        let decoded_token =
            TokenClaims::from_token_with_validation(&token.token, "thisIsAFakeKey".as_bytes())
                .unwrap();

        assert_eq!(decoded_token.typ, u8::from(TokenType::SignIn));
        assert_eq!(decoded_token.uid, user_id);
        assert_eq!(decoded_token.eml, new_user.email);
        assert_eq!(decoded_token.cur, new_user.currency);
        assert!(
            decoded_token.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );
    }

    #[test]
    fn test_generate_token_pair() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let token = generate_token_pair(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            Duration::from_secs(5),
            "thisIsAFakeKey".as_bytes(),
        )
        .unwrap();

        assert!(!token.access_token.token.contains(&user_id.to_string()));
        assert!(!token.refresh_token.token.contains(&user_id.to_string()));

        let decoded_access_token = TokenClaims::from_token_with_validation(
            &token.access_token.token,
            "thisIsAFakeKey".as_bytes(),
        )
        .unwrap();

        assert_eq!(decoded_access_token.typ, u8::from(TokenType::Access));
        assert_eq!(decoded_access_token.uid, user_id);
        assert_eq!(decoded_access_token.eml, new_user.email);
        assert_eq!(decoded_access_token.cur, new_user.currency);
        assert!(
            decoded_access_token.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );

        let decoded_refresh_token = TokenClaims::from_token_with_validation(
            &token.refresh_token.token,
            "thisIsAFakeKey".as_bytes(),
        )
        .unwrap();

        assert_eq!(decoded_refresh_token.typ, u8::from(TokenType::Refresh));
        assert_eq!(decoded_refresh_token.uid, user_id);
        assert_eq!(decoded_refresh_token.eml, new_user.email);
        assert_eq!(decoded_refresh_token.cur, new_user.currency);
        assert!(
            decoded_refresh_token.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );
    }

    #[test]
    fn test_generate_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            TokenType::Access,
            Duration::from_secs(5),
            "thisIsAFakeKey".as_bytes(),
        )
        .unwrap();
        let refresh_token = generate_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            TokenType::Refresh,
            Duration::from_secs(5),
            "thisIsAFakeKey".as_bytes(),
        )
        .unwrap();
        let signin_token = generate_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            TokenType::SignIn,
            Duration::from_secs(5),
            "thisIsAFakeKey".as_bytes(),
        )
        .unwrap();

        let decoded_access_token = TokenClaims::from_token_with_validation(
            &access_token.token,
            "thisIsAFakeKey".as_bytes(),
        )
        .unwrap();

        let decoded_refresh_token = TokenClaims::from_token_with_validation(
            &refresh_token.token,
            "thisIsAFakeKey".as_bytes(),
        )
        .unwrap();

        let decoded_signin_token = TokenClaims::from_token_with_validation(
            &signin_token.token,
            "thisIsAFakeKey".as_bytes(),
        )
        .unwrap();

        assert_eq!(decoded_access_token.typ, u8::from(TokenType::Access));
        assert_eq!(decoded_access_token.uid, user_id);
        assert_eq!(decoded_access_token.eml, new_user.email);
        assert_eq!(decoded_access_token.cur, new_user.currency);
        assert!(
            decoded_access_token.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );

        assert_eq!(decoded_refresh_token.typ, u8::from(TokenType::Refresh));
        assert_eq!(decoded_refresh_token.uid, user_id);
        assert_eq!(decoded_refresh_token.eml, new_user.email);
        assert_eq!(decoded_refresh_token.cur, new_user.currency);
        assert!(
            decoded_refresh_token.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );

        assert_eq!(decoded_signin_token.typ, u8::from(TokenType::SignIn));
        assert_eq!(decoded_signin_token.uid, user_id);
        assert_eq!(decoded_signin_token.eml, new_user.email);
        assert_eq!(decoded_signin_token.cur, new_user.currency);
        assert!(
            decoded_signin_token.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );
    }

    #[test]
    fn test_validate_access_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_access_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();
        let refresh_token = generate_refresh_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();
        let signin_token = generate_signin_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();

        assert_eq!(
            validate_access_token(
                &access_token.token,
                vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice()
            )
            .unwrap()
            .uid,
            user_id
        );
        assert!(validate_access_token(
            &refresh_token.token,
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice()
        )
        .is_err());
        assert!(validate_access_token(
            &signin_token.token,
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice()
        )
        .is_err());
    }

    #[test]
    fn test_validate_refresh_token() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;

        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_access_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();
        let refresh_token = generate_refresh_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 3, 10, 11].as_slice(),
        )
        .unwrap();
        let signin_token = generate_signin_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();

        let mut dao = AuthDao::new(db_thread_pool);

        assert_eq!(
            validate_refresh_token(
                &refresh_token.token,
                vec![32, 4, 23, 53, 75, 23, 3, 10, 11].as_slice(),
                &mut dao
            )
            .unwrap()
            .uid,
            user_id
        );
        assert!(validate_refresh_token(
            &access_token.token,
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
            &mut dao
        )
        .is_err());
        assert!(validate_refresh_token(
            &signin_token.token,
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
            &mut dao
        )
        .is_err());
    }

    #[test]
    fn test_validate_signin_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_access_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();
        let refresh_token = generate_refresh_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();
        let signin_token = generate_signin_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();

        assert_eq!(
            validate_signin_token(
                &signin_token.token,
                vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice()
            )
            .unwrap()
            .uid,
            user_id
        );
        assert!(validate_signin_token(
            &access_token.token,
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11, 0].as_slice()
        )
        .is_err());
        assert!(validate_signin_token(
            &refresh_token.token,
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice()
        )
        .is_err());
    }

    #[test]
    fn test_validate_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_access_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();
        let refresh_token = generate_refresh_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();
        let signin_token = generate_signin_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();

        assert_eq!(
            validate_token(
                &access_token.token,
                TokenType::Access,
                vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice()
            )
            .unwrap()
            .uid,
            user_id
        );
        assert_eq!(
            validate_token(
                &refresh_token.token,
                TokenType::Refresh,
                vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice()
            )
            .unwrap()
            .uid,
            user_id,
        );
        assert_eq!(
            validate_token(
                &signin_token.token,
                TokenType::SignIn,
                vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice()
            )
            .unwrap()
            .uid,
            user_id,
        );
    }

    #[test]
    fn test_validate_tokens_does_not_validate_tokens_of_wrong_type() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_access_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();
        let refresh_token = generate_refresh_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();
        let signin_token = generate_signin_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();

        assert!(validate_token(
            &access_token.token,
            TokenType::SignIn,
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice()
        )
        .is_err());
        assert!(validate_token(
            &refresh_token.token,
            TokenType::Access,
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice()
        )
        .is_err());
        assert!(validate_token(
            &signin_token.token,
            TokenType::Refresh,
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice()
        )
        .is_err());
    }

    #[test]
    fn test_read_claims() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_access_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();
        let refresh_token = generate_refresh_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();
        let signin_token = generate_signin_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();

        let access_token_claims =
            TokenClaims::from_token_without_validation(&access_token.to_string()).unwrap();
        let refresh_token_claims =
            TokenClaims::from_token_without_validation(&refresh_token.to_string()).unwrap();
        let signin_token_claims =
            TokenClaims::from_token_without_validation(&signin_token.to_string()).unwrap();

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(access_token_claims.uid, user_id);
        assert_eq!(access_token_claims.typ, u8::from(TokenType::Access));
        assert!(access_token_claims.exp > current_time);

        assert_eq!(refresh_token_claims.uid, user_id);
        assert_eq!(refresh_token_claims.typ, u8::from(TokenType::Refresh));
        assert!(refresh_token_claims.exp > current_time);

        assert_eq!(signin_token_claims.uid, user_id);
        assert_eq!(signin_token_claims.typ, u8::from(TokenType::SignIn));
        assert!(signin_token_claims.exp > current_time);
    }

    #[test]
    fn test_blacklist_token() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut db_connection = db_thread_pool.get().unwrap();

        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        dsl::insert_into(users)
            .values(&new_user)
            .execute(&mut db_connection)
            .unwrap();

        let refresh_token = generate_refresh_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();

        let mut dao = AuthDao::new(db_thread_pool);
        blacklist_token(&refresh_token.token, &mut dao).unwrap();

        // Should panic if none are found
        blacklisted_tokens
            .filter(blacklisted_token_fields::token.eq(&refresh_token.token))
            .first::<BlacklistedToken>(&mut db_connection)
            .unwrap();
    }

    #[test]
    fn test_is_token_on_blacklist() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut db_connection = db_thread_pool.get().unwrap();

        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        dsl::insert_into(users)
            .values(&new_user)
            .execute(&mut db_connection)
            .unwrap();

        let refresh_token = generate_refresh_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();

        let mut dao = AuthDao::new(db_thread_pool);
        assert!(!is_on_blacklist(&refresh_token.token, &mut dao).unwrap());

        blacklist_token(&refresh_token.token, &mut dao).unwrap();
        assert!(is_on_blacklist(&refresh_token.token, &mut dao).unwrap());
    }

    #[test]
    fn test_is_access_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_access_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();

        assert!(access_token.is_access_token());
        assert!(!access_token.is_refresh_token());
        assert!(!access_token.is_signin_token());
    }

    #[test]
    fn test_is_refresh_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let refresh_token = generate_refresh_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();

        assert!(refresh_token.is_refresh_token());
        assert!(!refresh_token.is_access_token());
        assert!(!refresh_token.is_signin_token());
    }

    #[test]
    fn test_is_signin_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let timestamp = SystemTime::now();
        let new_user = NewUser {
            id: user_id,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number),
            last_name: &format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let signin_token = generate_signin_token(
            &TokenParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            Duration::from_secs(5),
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();

        assert!(signin_token.is_signin_token());
        assert!(!signin_token.is_access_token());
        assert!(!signin_token.is_refresh_token());
    }
}
