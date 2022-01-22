use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::definitions::*;
use crate::env;
use crate::models::blacklisted_token::{BlacklistedToken, NewBlacklistedToken};
use crate::schema::blacklisted_tokens as blacklisted_token_fields;
use crate::schema::blacklisted_tokens::dsl::blacklisted_tokens;

#[derive(Debug)]
pub enum JwtError {
    DatabaseError(diesel::result::Error),
    DecodingError(jsonwebtoken::errors::Error),
    EncodingError(jsonwebtoken::errors::Error),
    InvalidTokenType(TokenTypeError),
    TokenInvalid,
    TokenBlacklisted,
    TokenExpired,
    SystemResourceAccessFailure,
    WrongTokenType,

    #[doc(hidden)]
    __Nonexhaustive,
}

impl std::error::Error for JwtError {}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtError::DatabaseError(e) => write!(f, "DatabaseError: {}", e),
            JwtError::DecodingError(e) => write!(f, "DecodingError: {}", e),
            JwtError::EncodingError(e) => write!(f, "EncodingError: {}", e),
            JwtError::InvalidTokenType(e) => write!(f, "InvalidTokenType: {}", e),
            _ => write!(f, "Error: {}", self.to_string()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
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
pub struct JwtParams<'a> {
    pub user_id: &'a Uuid,
    pub user_email: &'a str,
    pub user_currency: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub exp: u64,    // Expiration in time since UNIX epoch
    pub uid: Uuid,   // User ID
    pub eml: String, // User email address
    pub cur: String, // User currency
    pub typ: u8,     // Token type (Access=0, Refresh=1, SignIn=2)
    pub slt: u32,    // Random salt (makes it so two tokens generated in the same
                     //              second are different--useful for testing)
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
        if let TokenType::Access = self.token_type {
            true
        } else {
            false
        }
    }

    #[allow(dead_code)]
    fn is_refresh_token(&self) -> bool {
        if let TokenType::Refresh = self.token_type {
            true
        } else {
            false
        }
    }

    #[allow(dead_code)]
    fn is_signin_token(&self) -> bool {
        if let TokenType::SignIn = self.token_type {
            true
        } else {
            false
        }
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

pub fn generate_access_token(params: JwtParams) -> Result<Token, JwtError> {
    Ok(generate_token(params, TokenType::Access)?)
}

pub fn generate_refresh_token(params: JwtParams) -> Result<Token, JwtError> {
    Ok(generate_token(params, TokenType::Refresh)?)
}

pub fn generate_signin_token(params: JwtParams) -> Result<Token, JwtError> {
    Ok(generate_token(params, TokenType::SignIn)?)
}

pub fn generate_token_pair(params: JwtParams) -> Result<TokenPair, JwtError> {
    let access_token = generate_access_token(params.clone())?;
    let refresh_token = generate_refresh_token(params)?;

    Ok(TokenPair {
        access_token,
        refresh_token,
    })
}

fn generate_token(params: JwtParams, token_type: TokenType) -> Result<Token, JwtError> {
    let lifetime_sec = match token_type {
        TokenType::Access => env::CONF.lifetimes.access_token_lifetime_mins * 60,
        TokenType::Refresh => env::CONF.lifetimes.refresh_token_lifetime_days * 24 * 60 * 60,
        // Because of how the one-time passcodes expire, a future passcode is sent to the user.
        // The verification endpoint checks the current code and the next (future) code, meaning
        // a user's code will be valid for a maximum of OTP_LIFETIME_SECS * 2.
        TokenType::SignIn => env::CONF.lifetimes.otp_lifetime_mins * 60 * 2,
    };

    let time_since_epoch = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(t) => t,
        Err(_) => return Err(JwtError::from(JwtError::SystemResourceAccessFailure)),
    };

    let expiration = time_since_epoch.as_secs() + lifetime_sec;
    let salt = rand::thread_rng().gen_range(1..u32::MAX);

    let claims = TokenClaims {
        exp: expiration,
        uid: *params.user_id,
        eml: params.user_email.to_string(),
        cur: params.user_currency.to_string(),
        typ: token_type.clone().into(),
        slt: salt,
    };

    let mut header = Header::default();
    header.alg = Algorithm::HS256;

    let token = match jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_secret(env::CONF.keys.signing_key.as_bytes()),
    ) {
        Ok(t) => Ok(t),
        Err(e) => Err(JwtError::from(JwtError::EncodingError(e))),
    };

    Ok(Token {
        token: token?,
        token_type,
    })
}

pub fn validate_access_token(token: &str) -> Result<TokenClaims, JwtError> {
    validate_token(token, TokenType::Access)
}

pub fn validate_refresh_token(
    token: &str,
    db_connection: &DbConnection,
) -> Result<TokenClaims, JwtError> {
    if is_on_blacklist(token, &db_connection)? {
        return Err(JwtError::from(JwtError::TokenBlacklisted));
    }

    validate_token(token, TokenType::Refresh)
}

pub fn validate_signin_token(token: &str) -> Result<TokenClaims, JwtError> {
    validate_token(token, TokenType::SignIn)
}

fn validate_token(token: &str, token_type: TokenType) -> Result<TokenClaims, JwtError> {
    let decoded_token = match jsonwebtoken::decode::<TokenClaims>(
        &token,
        &DecodingKey::from_secret(env::CONF.keys.signing_key.as_bytes()),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(t) => t,
        Err(e) => {
            return match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    Err(JwtError::from(JwtError::TokenExpired))
                }
                jsonwebtoken::errors::ErrorKind::InvalidToken
                | jsonwebtoken::errors::ErrorKind::InvalidSignature
                | jsonwebtoken::errors::ErrorKind::InvalidEcdsaKey
                | jsonwebtoken::errors::ErrorKind::InvalidRsaKey
                | jsonwebtoken::errors::ErrorKind::InvalidAlgorithmName
                | jsonwebtoken::errors::ErrorKind::InvalidKeyFormat
                | jsonwebtoken::errors::ErrorKind::InvalidIssuer
                | jsonwebtoken::errors::ErrorKind::InvalidAudience
                | jsonwebtoken::errors::ErrorKind::InvalidSubject
                | jsonwebtoken::errors::ErrorKind::ImmatureSignature
                | jsonwebtoken::errors::ErrorKind::InvalidAlgorithm => {
                    Err(JwtError::from(JwtError::TokenInvalid))
                }
                _ => Err(JwtError::from(JwtError::DecodingError(e))),
            }
        }
    };

    let token_type_claim = match TokenType::try_from(decoded_token.claims.typ) {
        Ok(t) => t,
        Err(e) => return Err(JwtError::from(JwtError::InvalidTokenType(e))),
    };

    if std::mem::discriminant(&token_type_claim) != std::mem::discriminant(&token_type) {
        Err(JwtError::from(JwtError::WrongTokenType))
    } else {
        Ok(decoded_token.claims)
    }
}

#[allow(dead_code)]
pub fn read_claims(token: &str) -> Result<TokenClaims, JwtError> {
    match jsonwebtoken::dangerous_insecure_decode::<TokenClaims>(token) {
        Ok(c) => Ok(c.claims),
        Err(e) => Err(JwtError::from(JwtError::DecodingError(e))),
    }
}

pub fn blacklist_token(
    token: &str,
    db_connection: &DbConnection,
) -> Result<BlacklistedToken, JwtError> {
    let decoded_token = match jsonwebtoken::dangerous_insecure_decode::<TokenClaims>(&token) {
        Ok(t) => t,
        Err(e) => {
            return match e.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken
                | jsonwebtoken::errors::ErrorKind::InvalidSignature
                | jsonwebtoken::errors::ErrorKind::InvalidEcdsaKey
                | jsonwebtoken::errors::ErrorKind::InvalidRsaKey
                | jsonwebtoken::errors::ErrorKind::InvalidAlgorithmName
                | jsonwebtoken::errors::ErrorKind::InvalidKeyFormat
                | jsonwebtoken::errors::ErrorKind::InvalidIssuer
                | jsonwebtoken::errors::ErrorKind::InvalidAudience
                | jsonwebtoken::errors::ErrorKind::InvalidSubject
                | jsonwebtoken::errors::ErrorKind::ImmatureSignature
                | jsonwebtoken::errors::ErrorKind::InvalidAlgorithm => {
                    Err(JwtError::from(JwtError::TokenInvalid))
                }
                _ => Err(JwtError::from(JwtError::DecodingError(e))),
            }
        }
    };

    let user_id = decoded_token.claims.uid;
    let expiration = decoded_token.claims.exp;

    let blacklisted_token = NewBlacklistedToken {
        token: token,
        user_id: user_id,
        token_expiration_time: match i64::try_from(expiration) {
            Ok(exp) => exp,
            Err(_) => return Err(JwtError::from(JwtError::TokenInvalid)),
        },
    };

    match dsl::insert_into(blacklisted_tokens)
        .values(&blacklisted_token)
        .get_result::<BlacklistedToken>(db_connection)
    {
        Ok(t) => Ok(t),
        Err(e) => Err(JwtError::from(JwtError::DatabaseError(e))),
    }
}

pub fn is_on_blacklist(token: &str, db_connection: &DbConnection) -> Result<bool, JwtError> {
    match blacklisted_tokens
        .filter(blacklisted_token_fields::token.eq(token))
        .limit(1)
        .get_result::<BlacklistedToken>(db_connection)
    {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::NaiveDate;

    use crate::models::user::NewUser;
    use crate::schema::users::dsl::users;

    #[test]
    fn test_generate_access_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let token = generate_access_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        assert!(!token.token.contains(&user_id.to_string()));

        let decoded_token = jsonwebtoken::decode::<TokenClaims>(
            &token.token,
            &DecodingKey::from_secret(env::CONF.keys.signing_key.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();

        assert_eq!(decoded_token.claims.typ, u8::from(TokenType::Access));
        assert_eq!(decoded_token.claims.uid, user_id);
        assert_eq!(decoded_token.claims.eml, new_user.email);
        assert_eq!(decoded_token.claims.cur, new_user.currency);
        assert!(
            decoded_token.claims.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );
    }

    #[test]
    fn test_generate_refresh_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let token = generate_refresh_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        assert!(!token.token.contains(&user_id.to_string()));

        let decoded_token = jsonwebtoken::decode::<TokenClaims>(
            &token.token,
            &DecodingKey::from_secret(env::CONF.keys.signing_key.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();

        assert_eq!(decoded_token.claims.typ, u8::from(TokenType::Refresh));
        assert_eq!(decoded_token.claims.uid, user_id);
        assert_eq!(decoded_token.claims.eml, new_user.email);
        assert_eq!(decoded_token.claims.cur, new_user.currency);
        assert!(
            decoded_token.claims.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );
    }

    #[test]
    fn test_generate_signin_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let token = generate_signin_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        assert!(!token.token.contains(&user_id.to_string()));

        let decoded_token = jsonwebtoken::decode::<TokenClaims>(
            &token.token,
            &DecodingKey::from_secret(env::CONF.keys.signing_key.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();

        assert_eq!(decoded_token.claims.typ, u8::from(TokenType::SignIn));
        assert_eq!(decoded_token.claims.uid, user_id);
        assert_eq!(decoded_token.claims.eml, new_user.email);
        assert_eq!(decoded_token.claims.cur, new_user.currency);
        assert!(
            decoded_token.claims.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );
    }

    #[test]
    fn test_generate_token_pair() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let token = generate_token_pair(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        assert!(!token.access_token.token.contains(&user_id.to_string()));
        assert!(!token.refresh_token.token.contains(&user_id.to_string()));

        let decoded_access_token = jsonwebtoken::decode::<TokenClaims>(
            &token.access_token.token,
            &DecodingKey::from_secret(env::CONF.keys.signing_key.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();

        assert_eq!(decoded_access_token.claims.typ, u8::from(TokenType::Access));
        assert_eq!(decoded_access_token.claims.uid, user_id);
        assert_eq!(decoded_access_token.claims.eml, new_user.email);
        assert_eq!(decoded_access_token.claims.cur, new_user.currency);
        assert!(
            decoded_access_token.claims.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );

        let decoded_refresh_token = jsonwebtoken::decode::<TokenClaims>(
            &token.refresh_token.token,
            &DecodingKey::from_secret(env::CONF.keys.signing_key.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();

        assert_eq!(
            decoded_refresh_token.claims.typ,
            u8::from(TokenType::Refresh)
        );
        assert_eq!(decoded_refresh_token.claims.uid, user_id);
        assert_eq!(decoded_refresh_token.claims.eml, new_user.email);
        assert_eq!(decoded_refresh_token.claims.cur, new_user.currency);
        assert!(
            decoded_refresh_token.claims.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );
    }

    #[test]
    fn test_generate_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_token(
            JwtParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            TokenType::Access,
        )
        .unwrap();
        let refresh_token = generate_token(
            JwtParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            TokenType::Refresh,
        )
        .unwrap();
        let signin_token = generate_token(
            JwtParams {
                user_id: &new_user.id,
                user_email: new_user.email,
                user_currency: new_user.currency,
            },
            TokenType::SignIn,
        )
        .unwrap();

        let decoded_access_token = jsonwebtoken::decode::<TokenClaims>(
            &access_token.token,
            &DecodingKey::from_secret(env::CONF.keys.signing_key.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();

        let decoded_refresh_token = jsonwebtoken::decode::<TokenClaims>(
            &refresh_token.token,
            &DecodingKey::from_secret(env::CONF.keys.signing_key.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();

        let decoded_signin_token = jsonwebtoken::decode::<TokenClaims>(
            &signin_token.token,
            &DecodingKey::from_secret(env::CONF.keys.signing_key.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();

        assert_eq!(decoded_access_token.claims.typ, u8::from(TokenType::Access));
        assert_eq!(decoded_access_token.claims.uid, user_id);
        assert_eq!(decoded_access_token.claims.eml, new_user.email);
        assert_eq!(decoded_access_token.claims.cur, new_user.currency);
        assert!(
            decoded_access_token.claims.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );

        assert_eq!(
            decoded_refresh_token.claims.typ,
            u8::from(TokenType::Refresh)
        );
        assert_eq!(decoded_refresh_token.claims.uid, user_id);
        assert_eq!(decoded_refresh_token.claims.eml, new_user.email);
        assert_eq!(decoded_refresh_token.claims.cur, new_user.currency);
        assert!(
            decoded_refresh_token.claims.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );

        assert_eq!(decoded_signin_token.claims.typ, u8::from(TokenType::SignIn));
        assert_eq!(decoded_signin_token.claims.uid, user_id);
        assert_eq!(decoded_signin_token.claims.eml, new_user.email);
        assert_eq!(decoded_signin_token.claims.cur, new_user.currency);
        assert!(
            decoded_signin_token.claims.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );
    }

    #[test]
    fn test_validate_access_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_access_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();
        let refresh_token = generate_refresh_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();
        let signin_token = generate_signin_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        assert_eq!(
            validate_access_token(&access_token.token).unwrap().uid,
            user_id
        );
        assert!(match validate_access_token(&refresh_token.token) {
            Ok(_) => false,
            Err(_) => true,
        });
        assert!(match validate_access_token(&signin_token.token) {
            Ok(_) => false,
            Err(_) => true,
        });
    }

    #[test]
    fn test_validate_refresh_token() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_access_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();
        let refresh_token = generate_refresh_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();
        let signin_token = generate_signin_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        assert_eq!(
            validate_refresh_token(&refresh_token.token, &db_connection)
                .unwrap()
                .uid,
            user_id
        );
        assert!(
            match validate_refresh_token(&access_token.token, &db_connection) {
                Ok(_) => false,
                Err(_) => true,
            }
        );
        assert!(
            match validate_refresh_token(&signin_token.token, &db_connection) {
                Ok(_) => false,
                Err(_) => true,
            }
        );
    }

    #[test]
    fn test_validate_signin_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_access_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();
        let refresh_token = generate_refresh_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();
        let signin_token = generate_signin_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        assert_eq!(
            validate_signin_token(&signin_token.token).unwrap().uid,
            user_id
        );
        assert!(match validate_signin_token(&access_token.token) {
            Ok(_) => false,
            Err(_) => true,
        });
        assert!(match validate_signin_token(&refresh_token.token) {
            Ok(_) => false,
            Err(_) => true,
        });
    }

    #[test]
    fn test_validate_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_access_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();
        let refresh_token = generate_refresh_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();
        let signin_token = generate_signin_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        assert_eq!(
            validate_token(&access_token.token, TokenType::Access)
                .unwrap()
                .uid,
            user_id
        );
        assert_eq!(
            validate_token(&refresh_token.token, TokenType::Refresh)
                .unwrap()
                .uid,
            user_id
        );
        assert_eq!(
            validate_token(&signin_token.token, TokenType::SignIn)
                .unwrap()
                .uid,
            user_id
        );
    }

    #[test]
    fn test_validate_tokens_does_not_validate_tokens_of_wrong_type() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_access_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();
        let refresh_token = generate_refresh_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();
        let signin_token = generate_signin_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        assert!(
            match validate_token(&access_token.token, TokenType::SignIn) {
                Ok(_) => false,
                Err(_) => true,
            }
        );

        assert!(
            match validate_token(&refresh_token.token, TokenType::Access) {
                Ok(_) => false,
                Err(_) => true,
            }
        );

        assert!(
            match validate_token(&signin_token.token, TokenType::Refresh) {
                Ok(_) => false,
                Err(_) => true,
            }
        );
    }

    #[test]
    fn test_read_claims() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_access_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();
        let refresh_token = generate_refresh_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();
        let signin_token = generate_signin_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        let access_token_claims = read_claims(&access_token.to_string()).unwrap();
        let refresh_token_claims = read_claims(&refresh_token.to_string()).unwrap();
        let signin_token_claims = read_claims(&signin_token.to_string()).unwrap();

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
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        dsl::insert_into(users)
            .values(&new_user)
            .execute(&db_connection)
            .unwrap();

        let refresh_token = generate_refresh_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        let blacklist_token = blacklist_token(&refresh_token.token, &db_connection).unwrap();

        assert_eq!(&blacklist_token.token, &refresh_token.token);
        assert!(
            blacklist_token.token_expiration_time
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
        );

        blacklisted_tokens
            .filter(blacklisted_token_fields::token.eq(&refresh_token.token))
            .get_result::<BlacklistedToken>(&db_connection)
            .unwrap();
    }

    #[test]
    fn test_is_token_on_blacklist() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        dsl::insert_into(users)
            .values(&new_user)
            .execute(&db_connection)
            .unwrap();

        let refresh_token = generate_refresh_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        assert!(!is_on_blacklist(&refresh_token.token, &db_connection).unwrap());

        blacklist_token(&refresh_token.token, &db_connection).unwrap();

        assert!(is_on_blacklist(&refresh_token.token, &db_connection).unwrap());
    }

    #[test]
    fn test_is_access_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let access_token = generate_access_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        assert!(access_token.is_access_token());
        assert!(!access_token.is_refresh_token());
        assert!(!access_token.is_signin_token());
    }

    #[test]
    fn test_is_refresh_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let refresh_token = generate_refresh_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        assert!(refresh_token.is_refresh_token());
        assert!(!refresh_token.is_access_token());
        assert!(!refresh_token.is_signin_token());
    }

    #[test]
    fn test_is_signin_token() {
        let user_id = Uuid::new_v4();
        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
        let timestamp = chrono::Utc::now().naive_utc();
        let new_user = NewUser {
            id: user_id,
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &format!("test_user{}@test.com", &user_number).to_owned(),
            password_hash: "test_hash",
            first_name: &format!("Test-{}", &user_number).to_owned(),
            last_name: &format!("User-{}", &user_number).to_owned(),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        let signin_token = generate_signin_token(JwtParams {
            user_id: &new_user.id,
            user_email: new_user.email,
            user_currency: new_user.currency,
        })
        .unwrap();

        assert!(signin_token.is_signin_token());
        assert!(!signin_token.is_access_token());
        assert!(!signin_token.is_refresh_token());
    }
}
