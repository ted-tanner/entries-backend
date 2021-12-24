use diesel::r2d2::{ConnectionManager, PooledConnection};
use diesel::{dsl, ExpressionMethods, PgConnection, QueryDsl, RunQueryDsl};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::env;
use crate::models::blacklisted_token::{BlacklistedToken, NewBlacklistedToken};
use crate::schema::blacklisted_tokens as blacklisted_token_fields;
use crate::schema::blacklisted_tokens::dsl::blacklisted_tokens;

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub exp: u64,        // Expiration in time since UNIX epoch
    pub uid: uuid::Uuid, // User ID
    pub rfs: bool,       // Is refresh token
    pub slt: u16,        // Random salt (makes it so two tokens generated in the same
                         //              second are different--useful for testing)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InputBlacklistedRefreshToken {
    pub token: String,
    pub token_expiration_epoch: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AccessToken(String);

impl ToString for AccessToken {
    fn to_string(&self) -> String {
        return self.0.clone();
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RefreshToken(String);

impl ToString for RefreshToken {
    fn to_string(&self) -> String {
        return self.0.clone();
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenPair {
    pub access_token: AccessToken,
    pub refresh_token: RefreshToken,
}

impl TokenPair {
    pub fn empty() -> TokenPair {
        TokenPair {
            access_token: AccessToken(String::new()),
            refresh_token: RefreshToken(String::new()),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(ErrorKind);

impl Error {
    pub fn from(kind: ErrorKind) -> Error {
        Error(kind)
    }

    #[allow(dead_code)]
    pub fn kind(&self) -> &ErrorKind {
        return &self.0;
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ErrorKind: {}", self.0)
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    DatabaseError(diesel::result::Error),
    DecodingError(jsonwebtoken::errors::Error),
    EncodingError(jsonwebtoken::errors::Error),
    TokenInvalid,
    TokenBlacklisted,
    TokenExpired,
    SystemResourceAccessFailure,
    WrongTokenType,

    #[doc(hidden)]
    __Nonexhaustive,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ErrorKind: {}", self.to_string())
    }
}

pub fn generate_access_token(user_id: uuid::Uuid) -> Result<AccessToken> {
    Ok(AccessToken(generate_token(user_id, false)?))
}

pub fn generate_refresh_token(user_id: uuid::Uuid) -> Result<RefreshToken> {
    Ok(RefreshToken(generate_token(user_id, true)?))
}

pub fn generate_token_pair(user_id: uuid::Uuid) -> Result<TokenPair> {
    let access_token = generate_access_token(user_id)?;
    let refresh_token = generate_refresh_token(user_id)?;

    Ok(TokenPair {
        access_token,
        refresh_token,
    })
}

fn generate_token(user_id: uuid::Uuid, is_refresh: bool) -> Result<String> {
    let lifetime_sec = if is_refresh {
        *env::jwt::REFRESH_LIFETIME_DAYS
    } else {
        *env::jwt::ACCESS_LIFETIME_SEC
    };

    let time_since_epoch = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(t) => t,
        Err(_) => return Err(Error::from(ErrorKind::SystemResourceAccessFailure)),
    };

    let expiration = time_since_epoch.as_secs() + lifetime_sec;
    let salt = rand::thread_rng().gen_range(1..u16::MAX);

    let claims = TokenClaims {
        exp: expiration,
        uid: user_id,
        rfs: is_refresh,
        slt: salt,
    };

    let mut header = Header::default();
    header.alg = Algorithm::HS256;

    match jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_secret(env::jwt::SIGNING_SECRET_KEY.as_bytes()),
    ) {
        Ok(t) => Ok(t),
        Err(e) => Err(Error::from(ErrorKind::EncodingError(e))),
    }
}

pub fn validate_access_token(token: &str) -> Result<TokenClaims> {
    validate_token(token, false)
}

pub fn validate_refresh_token(
    token: &str,
    db_connection: &PooledConnection<ConnectionManager<PgConnection>>,
) -> Result<TokenClaims> {
    if is_on_blacklist(token, &db_connection)? {
        return Err(Error::from(ErrorKind::TokenBlacklisted));
    }

    validate_token(token, true)
}

fn validate_token(token: &str, is_refresh: bool) -> Result<TokenClaims> {
    let decoded_token = match jsonwebtoken::decode::<TokenClaims>(
        &token,
        &DecodingKey::from_secret(env::jwt::SIGNING_SECRET_KEY.as_bytes()),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(t) => t,
        Err(e) => {
            return match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    Err(Error::from(ErrorKind::TokenExpired))
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
                    Err(Error::from(ErrorKind::TokenInvalid))
                }
                _ => Err(Error::from(ErrorKind::DecodingError(e))),
            }
        }
    };

    if decoded_token.claims.rfs != is_refresh {
        Err(Error::from(ErrorKind::WrongTokenType))
    } else {
        Ok(decoded_token.claims)
    }
}

pub fn read_claims(token: &str) -> Result<TokenClaims> {
    match jsonwebtoken::dangerous_insecure_decode::<TokenClaims>(token) {
        Ok(c) => Ok(c.claims),
        Err(e) => Err(Error::from(ErrorKind::DecodingError(e))),
    }
}

pub fn blacklist_token(
    token: &str,
    db_connection: &PooledConnection<ConnectionManager<PgConnection>>,
) -> Result<BlacklistedToken> {
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
                    Err(Error::from(ErrorKind::TokenInvalid))
                }
                _ => Err(Error::from(ErrorKind::DecodingError(e))),
            }
        }
    };

    let user_id = decoded_token.claims.uid;
    let expiration = decoded_token.claims.exp;

    let blacklisted_token = NewBlacklistedToken {
        token: token,
        user_id: user_id,
        token_expiration_epoch: match i64::try_from(expiration) {
            Ok(exp) => exp,
            Err(_) => return Err(Error::from(ErrorKind::TokenInvalid)),
        },
    };

    match dsl::insert_into(blacklisted_tokens)
        .values(&blacklisted_token)
        .get_result::<BlacklistedToken>(db_connection)
    {
        Ok(t) => Ok(t),
        Err(e) => Err(Error::from(ErrorKind::DatabaseError(e))),
    }
}

pub fn is_on_blacklist(
    token: &str,
    db_connection: &PooledConnection<ConnectionManager<PgConnection>>,
) -> Result<bool> {
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
mod test {
    use super::*;

    use chrono::NaiveDate;

    use crate::models::user::NewUser;
    use crate::schema::users::dsl::users;

    #[test]
    fn test_generate_access_token() {
        let user_id = uuid::Uuid::new_v4();

        let token = generate_access_token(user_id).unwrap();

        assert!(!token.0.contains(&user_id.to_string()));

        let decoded_token = jsonwebtoken::decode::<TokenClaims>(
            &token.0,
            &DecodingKey::from_secret(env::jwt::SIGNING_SECRET_KEY.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();

        assert!(!decoded_token.claims.rfs);
        assert_eq!(decoded_token.claims.uid, user_id);
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
        let user_id = uuid::Uuid::new_v4();

        let token = generate_refresh_token(user_id).unwrap();

        assert!(!token.0.contains(&user_id.to_string()));

        let decoded_token = jsonwebtoken::decode::<TokenClaims>(
            &token.0,
            &DecodingKey::from_secret(env::jwt::SIGNING_SECRET_KEY.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();

        assert!(decoded_token.claims.rfs);
        assert_eq!(decoded_token.claims.uid, user_id);
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
        let user_id = uuid::Uuid::new_v4();

        let token = generate_token_pair(user_id).unwrap();

        assert!(!token.access_token.0.contains(&user_id.to_string()));
        assert!(!token.refresh_token.0.contains(&user_id.to_string()));

        let decoded_access_token = jsonwebtoken::decode::<TokenClaims>(
            &token.access_token.0,
            &DecodingKey::from_secret(env::jwt::SIGNING_SECRET_KEY.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();

        assert!(!decoded_access_token.claims.rfs);
        assert_eq!(decoded_access_token.claims.uid, user_id);
        assert!(
            decoded_access_token.claims.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );

        let decoded_refresh_token = jsonwebtoken::decode::<TokenClaims>(
            &token.refresh_token.0,
            &DecodingKey::from_secret(env::jwt::SIGNING_SECRET_KEY.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();

        assert!(decoded_refresh_token.claims.rfs);
        assert_eq!(decoded_refresh_token.claims.uid, user_id);
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
        let user_id = uuid::Uuid::new_v4();

        let access_token = generate_token(user_id, false).unwrap();
        let refresh_token = generate_token(user_id, true).unwrap();

        let decoded_access_token = jsonwebtoken::decode::<TokenClaims>(
            &access_token,
            &DecodingKey::from_secret(env::jwt::SIGNING_SECRET_KEY.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();

        let decoded_refresh_token = jsonwebtoken::decode::<TokenClaims>(
            &refresh_token,
            &DecodingKey::from_secret(env::jwt::SIGNING_SECRET_KEY.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();

        assert!(!decoded_access_token.claims.rfs);
        assert_eq!(decoded_access_token.claims.uid, user_id);
        assert!(
            decoded_access_token.claims.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );

        assert!(decoded_refresh_token.claims.rfs);
        assert_eq!(decoded_refresh_token.claims.uid, user_id);
        assert!(
            decoded_refresh_token.claims.exp
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );
    }

    #[test]
    fn test_validate_access_token() {
        let user_id = uuid::Uuid::new_v4();

        let access_token = generate_access_token(user_id).unwrap();
        let refresh_token = generate_refresh_token(user_id).unwrap();

        assert_eq!(validate_access_token(&access_token.0).unwrap().uid, user_id);
        assert!(match validate_access_token(&refresh_token.0) {
            Ok(_) => false,
            Err(_) => true,
        });
    }

    #[test]
    fn test_validate_refresh_token() {
        let thread_pool = &env::testing::THREAD_POOL;
        let db_connection = thread_pool.get().unwrap();

        let user_id = uuid::Uuid::new_v4();

        let access_token = generate_access_token(user_id).unwrap();
        let refresh_token = generate_refresh_token(user_id).unwrap();

        assert_eq!(
            validate_refresh_token(&refresh_token.0, &db_connection)
                .unwrap()
                .uid,
            user_id
        );
        assert!(
            match validate_refresh_token(&access_token.0, &db_connection) {
                Ok(_) => false,
                Err(_) => true,
            }
        );
    }

    #[test]
    fn test_validate_token() {
        let user_id = uuid::Uuid::new_v4();

        let access_token = generate_access_token(user_id).unwrap();
        let refresh_token = generate_refresh_token(user_id).unwrap();

        assert_eq!(validate_token(&access_token.0, false).unwrap().uid, user_id);
        assert_eq!(validate_token(&refresh_token.0, true).unwrap().uid, user_id);

        assert!(match validate_token(&access_token.0, true) {
            Ok(_) => false,
            Err(_) => true,
        });

        assert!(match validate_token(&refresh_token.0, false) {
            Ok(_) => false,
            Err(_) => true,
        });
    }

    #[test]
    fn test_read_claims() {
        let user_id = uuid::Uuid::new_v4();

        let access_token = generate_access_token(user_id).unwrap();
        let refresh_token = generate_refresh_token(user_id).unwrap();

        let access_token_claims = read_claims(&access_token.to_string()).unwrap();
        let refresh_token_claims = read_claims(&refresh_token.to_string()).unwrap();

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(access_token_claims.uid, user_id);
        assert_eq!(access_token_claims.rfs, false);
        assert!(access_token_claims.exp > current_time);

        assert_eq!(refresh_token_claims.uid, user_id);
        assert_eq!(refresh_token_claims.rfs, true);
        assert!(refresh_token_claims.exp > current_time);
    }

    #[test]
    fn test_blacklist_token() {
        let thread_pool = &env::testing::THREAD_POOL;
        let db_connection = thread_pool.get().unwrap();

        let user_id = uuid::Uuid::new_v4();

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
            date_of_birth: NaiveDate::from_ymd(2015, 03, 14),
            currency: "USD",
            modified_timestamp: timestamp,
            created_timestamp: timestamp,
        };

        dsl::insert_into(users)
            .values(&new_user)
            .execute(&db_connection)
            .unwrap();

        let refresh_token = generate_refresh_token(user_id).unwrap();

        let blacklist_token = blacklist_token(&refresh_token.0, &db_connection).unwrap();

        assert_eq!(&blacklist_token.token, &refresh_token.0);
        assert!(
            blacklist_token.token_expiration_epoch
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
        );

        blacklisted_tokens
            .filter(blacklisted_token_fields::token.eq(&refresh_token.0))
            .get_result::<BlacklistedToken>(&db_connection)
            .unwrap();
    }

    #[test]
    fn test_is_token_on_blacklist() {
        let thread_pool = &env::testing::THREAD_POOL;
        let db_connection = thread_pool.get().unwrap();

        let user_id = uuid::Uuid::new_v4();

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

        let refresh_token = generate_refresh_token(user_id).unwrap();

        assert!(!is_on_blacklist(&refresh_token.0, &db_connection).unwrap());

        blacklist_token(&refresh_token.0, &db_connection).unwrap();

        assert!(is_on_blacklist(&refresh_token.0, &db_connection).unwrap());
    }
}
