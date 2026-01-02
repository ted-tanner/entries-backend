use entries_common::db::{self, DaoError, DbThreadPool};
use entries_common::email::templates::UserVerificationMessage;
use entries_common::email::{EmailMessage, EmailSender};
use entries_common::messages::{
    AuthenticatedSession, CredentialPair, EmailQuery, RecoveryKeyAuthAndPasswordUpdate,
    SigninNonceAndHashParams, SigninToken,
};
use entries_common::messages::{Otp as OtpMessage, TokenPair};
use entries_common::token::auth_token::{AuthToken, AuthTokenType, NewAuthTokenClaims};
use entries_common::validators::{self, Validity};

use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
use actix_web::{web, HttpResponse};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use crate::env;
use crate::handlers::{self, error::HttpErrorResponse};
use crate::middleware::auth::{Access, Refresh, SignIn, UnverifiedToken, VerifiedToken};
use crate::middleware::FromHeader;
use crate::utils::limiter_table as rate_limit_table;
use crate::utils::limiter_table::CheckAndRecordResult;
use crate::utils::limiter_table::LimiterTable;

struct SigninLimiter {
    max_per_period: u32,
    period: Duration,
    clear_frequency: Duration,
    tables: &'static [RwLock<LimiterTable<String>>; 16],
}

impl SigninLimiter {
    fn global() -> &'static Self {
        static LIMITER: OnceLock<SigninLimiter> = OnceLock::new();
        LIMITER.get_or_init(|| {
            rate_limit_table::init_start();
            Self {
                max_per_period: env::CONF.signin_limiter_max_per_period,
                period: env::CONF.signin_limiter_period,
                clear_frequency: env::CONF.signin_limiter_clear_frequency,
                tables: rate_limit_table::new_sharded_tables_16::<String>(),
            }
        })
    }

    #[cfg(test)]
    fn new_for_tests(max_per_period: u32, period: Duration, clear_frequency: Duration) -> Self {
        rate_limit_table::init_start();
        Self {
            max_per_period,
            period,
            clear_frequency,
            tables: rate_limit_table::new_sharded_tables_16::<String>(),
        }
    }

    #[inline]
    fn table_index(email: &str) -> usize {
        let bytes = email.as_bytes();

        #[allow(clippy::get_first)]
        let b0 = *bytes.get(0).unwrap_or(&0);
        let b1 = *bytes.get(1).unwrap_or(&0);

        (((b0 & 0x0F) ^ (b1 & 0x0F)) as usize) & 0x0F
    }

    async fn allow_attempt(&self, email: String) -> bool {
        let table_index = Self::table_index(&email);
        let shard = &self.tables[table_index];

        let now = Instant::now();
        let now_millis = rate_limit_table::now_millis_u32();

        match rate_limit_table::check_and_record(
            shard,
            email,
            now,
            now_millis,
            self.max_per_period,
            self.period,
            self.clear_frequency,
        )
        .await
        {
            CheckAndRecordResult::Allowed => true,
            CheckAndRecordResult::Blocked { .. } => false,
        }
    }
}

pub async fn obtain_nonce_and_auth_string_params(
    db_thread_pool: web::Data<DbThreadPool>,
    email: web::Query<EmailQuery>,
) -> Result<HttpResponse, HttpErrorResponse> {
    // Disguise that the user doesn't exist by returning random data that only changes
    // once per day. Do this even for valid requests to prevent timing attacks
    let unix_day = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86400;
    let mut rng = seed_chacha12rng_from_u64(unix_day);

    let random: u64 = rng.next_u64();

    let mut hasher = Sha256::new();
    hasher.update(email.email.as_bytes());
    hasher.update(random.to_be_bytes());
    hasher.update(env::CONF.token_signing_key);
    let hash = hasher.finalize();

    let phony_salt = hash[..16].to_vec();
    // The bounds are hardcoded. This is safe.
    let phony_nonce =
        unsafe { i32::from_be_bytes(hash.get_unchecked(16..20).try_into().unwrap_unchecked()) };

    let phony_params = SigninNonceAndHashParams {
        auth_string_hash_salt: phony_salt,
        auth_string_hash_mem_cost_kib: env::CONF.client_auth_string_hash_mem_cost_kib as _,
        auth_string_hash_threads: env::CONF.client_auth_string_hash_threads as _,
        auth_string_hash_iterations: env::CONF.client_auth_string_hash_iterations as _,
        nonce: phony_nonce,
    };

    let real_params = match web::block(move || {
        let auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.get_auth_string_data_signin_nonce(&email.0.email)
    })
    .await?
    {
        Ok(a) => a,
        Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
            return Ok(HttpResponse::Ok().protobuf(phony_params)?);
        }
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to obtain nonce or authentication string data",
            )));
        }
    };

    Ok(HttpResponse::Ok().protobuf(real_params)?)
}

// TODO: This function is needed until ed25519-dalek moves to rand 0.9, at which point entries_common
//       and entries_server can be updated to use rand 0.9 and rand_chacha can be updated to 0.9 that
//       has seed_from_u64()
fn seed_chacha12rng_from_u64(unix_day: u64) -> ChaCha12Rng {
    let seed = unix_day.to_le_bytes();
    let mut full_seed = [0u8; 32];
    full_seed[..8].copy_from_slice(&seed);
    ChaCha12Rng::from_seed(full_seed)
}

pub async fn sign_in(
    db_thread_pool: web::Data<DbThreadPool>,
    smtp_thread_pool: web::Data<EmailSender>,
    credentials: ProtoBuf<CredentialPair>,
) -> Result<HttpResponse, HttpErrorResponse> {
    if let Validity::Invalid(msg) = validators::validate_email_address(&credentials.0.email) {
        return Err(HttpErrorResponse::IncorrectlyFormed(String::from(msg)));
    }

    let email_limiter_key = credentials.0.email.to_ascii_lowercase();
    if !SigninLimiter::global()
        .allow_attempt(email_limiter_key)
        .await
    {
        return Err(HttpErrorResponse::TooManyAttempts(String::from(
            "Too many sign-in attempts. Please try again later.",
        )));
    }

    let credentials = Arc::new(credentials.0);
    let credentials_ref = Arc::clone(&credentials);

    let auth_dao = db::auth::Dao::new(&db_thread_pool);

    let nonce =
        match web::block(move || auth_dao.get_and_refresh_signin_nonce(&credentials_ref.email))
            .await?
        {
            Ok(a) => a,
            Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
                return Err(HttpErrorResponse::IncorrectCredential(String::from(
                    "The credentials were incorrect",
                )));
            }
            Err(e) => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to obtain sign-in nonce",
                )));
            }
        };

    if nonce != credentials.nonce {
        return Err(HttpErrorResponse::IncorrectNonce(String::from(
            "Incorrect nonce",
        )));
    }

    let credentials_ref = Arc::clone(&credentials);
    let auth_dao = db::auth::Dao::new(&db_thread_pool);

    let hash_and_status = match web::block(move || {
        auth_dao.get_user_auth_string_hash_and_status(&credentials_ref.email)
    })
    .await?
    {
        Ok(a) => a,
        Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
            return Err(HttpErrorResponse::IncorrectCredential(String::from(
                "The credentials were incorrect",
            )));
        }
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to get user auth string hash",
            )));
        }
    };

    if !hash_and_status.is_user_verified {
        let user_id = hash_and_status.user_id;
        let user_email = &credentials.email;

        // Send a new verification email
        let user_creation_token_claims = NewAuthTokenClaims {
            user_id,
            user_email,
            expiration: (hash_and_status.created_timestamp
                + env::CONF.user_creation_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .expect("System time should be after Unix Epoch")
                .as_secs(),
            token_type: AuthTokenType::UserCreation,
        };

        let user_creation_token =
            AuthToken::sign_new(user_creation_token_claims, &env::CONF.token_signing_key);

        let message = EmailMessage {
            body: UserVerificationMessage::generate(
                &env::CONF.user_verification_url,
                &user_creation_token,
                env::CONF.user_creation_token_lifetime,
            ),
            subject: "Verify your account",
            from: env::CONF.email_from_address.clone(),
            reply_to: env::CONF.email_reply_to_address.clone(),
            destination: user_email,
            is_html: true,
        };

        match smtp_thread_pool.send(message).await {
            Ok(_) => (),
            Err(e) => {
                log::error!("Failed to send verification email during sign-in attempt: {e}");
            }
        }

        return Err(HttpErrorResponse::PendingAction(String::from(
            "User has not accepted verification email. A new verification email has been sent.",
        )));
    }

    let user_id = hash_and_status.user_id;

    handlers::verification::verify_auth_string(
        &credentials.auth_string,
        &credentials.email,
        false,
        &db_thread_pool,
    )
    .await?;

    let signin_token_claims = NewAuthTokenClaims {
        user_id,
        user_email: &credentials.email,
        expiration: (SystemTime::now() + env::CONF.signin_token_lifetime)
            .duration_since(UNIX_EPOCH)
            .expect("System time should be after Unix Epoch")
            .as_secs(),
        token_type: AuthTokenType::SignIn,
    };

    let signin_token = AuthToken::sign_new(signin_token_claims, &env::CONF.token_signing_key);

    let signin_token = SigninToken {
        value: signin_token,
    };

    handlers::verification::generate_and_email_otp(
        &credentials.email,
        db_thread_pool.as_ref(),
        smtp_thread_pool.as_ref(),
    )
    .await?;

    Ok(HttpResponse::Ok().protobuf(signin_token)?)
}

pub async fn verify_otp_for_signin(
    db_thread_pool: web::Data<DbThreadPool>,
    signin_token: UnverifiedToken<SignIn, FromHeader>,
    otp: ProtoBuf<OtpMessage>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let claims = signin_token.verify()?;
    let user_id = claims.user_id;

    handlers::verification::verify_otp(&otp.value, &claims.user_email, &db_thread_pool).await?;

    let now = SystemTime::now();

    let refresh_token_claims = NewAuthTokenClaims {
        user_id,
        user_email: &claims.user_email,
        expiration: (now + env::CONF.refresh_token_lifetime)
            .duration_since(UNIX_EPOCH)
            .expect("System time should be after Unix Epoch")
            .as_secs(),
        token_type: AuthTokenType::Refresh,
    };

    let refresh_token = AuthToken::sign_new(refresh_token_claims, &env::CONF.token_signing_key);

    let access_token_claims = NewAuthTokenClaims {
        user_id,
        user_email: &claims.user_email,
        expiration: (now + env::CONF.access_token_lifetime)
            .duration_since(UNIX_EPOCH)
            .expect("System time should be after Unix Epoch")
            .as_secs(),
        token_type: AuthTokenType::Access,
    };

    let access_token = AuthToken::sign_new(access_token_claims, &env::CONF.token_signing_key);

    let token_pair = TokenPair {
        access_token,
        refresh_token,
        server_time: SystemTime::now().try_into()?,
    };

    let user_dao = db::user::Dao::new(&db_thread_pool);
    let protected_data = web::block(move || user_dao.get_protected_user_data(user_id))
        .await?
        .map_err(|e| {
            log::error!("Failed to get user protected data: {e}");
            HttpErrorResponse::InternalError(String::from("Failed to get user data"))
        })?;

    let authenticated_session = AuthenticatedSession {
        tokens: token_pair,
        preferences_encrypted: protected_data.preferences_encrypted,
        preferences_version_nonce: protected_data.preferences_version_nonce,
        user_keystore_encrypted: protected_data.user_keystore_encrypted,
        user_keystore_version_nonce: protected_data.user_keystore_version_nonce,
        password_encryption_key_salt: protected_data.password_encryption_key_salt,
        password_encryption_key_mem_cost_kib: protected_data.password_encryption_key_mem_cost_kib,
        password_encryption_key_threads: protected_data.password_encryption_key_threads,
        password_encryption_key_iterations: protected_data.password_encryption_key_iterations,
        encryption_key_encrypted_with_password: protected_data
            .encryption_key_encrypted_with_password,
    };

    Ok(HttpResponse::Ok().protobuf(authenticated_session)?)
}

pub async fn obtain_otp(
    db_thread_pool: web::Data<DbThreadPool>,
    smtp_thread_pool: web::Data<EmailSender>,
    user_access_token: VerifiedToken<Access, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    handlers::verification::generate_and_email_otp(
        &user_access_token.0.user_email,
        db_thread_pool.as_ref(),
        smtp_thread_pool.as_ref(),
    )
    .await?;

    Ok(HttpResponse::Ok().finish())
}

pub async fn refresh_tokens(
    db_thread_pool: web::Data<DbThreadPool>,
    token: UnverifiedToken<Refresh, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let token_claims = token.verify()?;
    let token_expiration = token_claims.expiration;

    match web::block(move || {
        let auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.check_is_token_on_blacklist_and_blacklist(&token.0.signature, token_expiration)
    })
    .await?
    {
        Ok(false) => (),
        Ok(true) => {
            return Err(HttpErrorResponse::TokenExpired(String::from(
                "Token has expired",
            )));
        }
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Error verifying token",
            )));
        }
    };

    let now = SystemTime::now();

    let refresh_token_claims = NewAuthTokenClaims {
        user_id: token_claims.user_id,
        user_email: &token_claims.user_email,
        expiration: (now + env::CONF.refresh_token_lifetime)
            .duration_since(UNIX_EPOCH)
            .expect("System time should be after Unix Epoch")
            .as_secs(),
        token_type: AuthTokenType::Refresh,
    };

    let refresh_token = AuthToken::sign_new(refresh_token_claims, &env::CONF.token_signing_key);

    let access_token_claims = NewAuthTokenClaims {
        user_id: token_claims.user_id,
        user_email: &token_claims.user_email,
        expiration: (now + env::CONF.access_token_lifetime)
            .duration_since(UNIX_EPOCH)
            .expect("System time should be after Unix Epoch")
            .as_secs(),
        token_type: AuthTokenType::Access,
    };

    let access_token = AuthToken::sign_new(access_token_claims, &env::CONF.token_signing_key);

    let token_pair = TokenPair {
        access_token,
        refresh_token,
        server_time: SystemTime::now().try_into()?,
    };

    Ok(HttpResponse::Ok().protobuf(token_pair)?)
}

pub async fn recover_with_recovery_key(
    db_thread_pool: web::Data<DbThreadPool>,
    recovery_key_data: ProtoBuf<RecoveryKeyAuthAndPasswordUpdate>,
) -> Result<HttpResponse, HttpErrorResponse> {
    if let Validity::Invalid(msg) =
        validators::validate_email_address(&recovery_key_data.user_email)
    {
        return Err(HttpErrorResponse::IncorrectlyFormed(String::from(msg)));
    }

    if let Some(email) = &recovery_key_data.new_user_email {
        if let Validity::Invalid(msg) = validators::validate_email_address(email) {
            return Err(HttpErrorResponse::IncorrectlyFormed(String::from(msg)));
        }
    }

    if recovery_key_data.new_auth_string.len() > env::CONF.max_auth_string_length {
        return Err(HttpErrorResponse::IncorrectlyFormed(String::from(
            "New auth string is too long",
        )));
    }

    if recovery_key_data.new_auth_string_hash_salt.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "New auth string salt is too big",
        )));
    }

    if recovery_key_data
        .new_recovery_key_hash_salt_for_encryption
        .len()
        > env::CONF.max_encryption_key_size
    {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "New recovery key hash salt for encryption is too big",
        )));
    }

    if recovery_key_data
        .new_recovery_key_hash_salt_for_recovery_auth
        .len()
        > env::CONF.max_encryption_key_size
    {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "New recovery key hash salt for recovery auth is too big",
        )));
    }

    if recovery_key_data.new_recovery_key_auth_hash.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "New recovery key auth hash is too big",
        )));
    }

    if recovery_key_data
        .encryption_key_encrypted_with_new_password
        .len()
        > env::CONF.max_encryption_key_size
    {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Encryption key encrypted with new password is too big",
        )));
    }

    if recovery_key_data
        .encryption_key_encrypted_with_new_recovery_key
        .len()
        > env::CONF.max_encryption_key_size
    {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Encryption key encrypted with new recovery key is too big",
        )));
    }

    handlers::verification::verify_auth_string(
        &recovery_key_data.recovery_key_hash_for_recovery_auth,
        &recovery_key_data.user_email,
        true,
        &db_thread_pool,
    )
    .await?;

    let recovery_key_data = Arc::new(recovery_key_data);

    let recovery_key_data_for_auth = Arc::clone(&recovery_key_data);
    let (sender_auth, receiver_auth) = tokio::sync::oneshot::channel();
    rayon::spawn(move || {
        let hash_result = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.auth_string_hash_salt_length)
            .hash_length(env::CONF.auth_string_hash_length)
            .iterations(env::CONF.auth_string_hash_iterations)
            .memory_cost_kib(env::CONF.auth_string_hash_mem_cost_kib)
            .threads(env::CONF.auth_string_hash_threads)
            .secret((&env::CONF.auth_string_hash_key).into())
            .hash(&recovery_key_data_for_auth.new_auth_string);
        let result = hash_result.map(|h| h.to_string());
        sender_auth
            .send(result)
            .expect("Failed to send auth hash result");
    });

    let recovery_key_data_for_recovery = Arc::clone(&recovery_key_data);
    let (sender_recovery, receiver_recovery) = tokio::sync::oneshot::channel();
    rayon::spawn(move || {
        let hash_result = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.auth_string_hash_salt_length)
            .hash_length(env::CONF.auth_string_hash_length)
            .iterations(env::CONF.auth_string_hash_iterations)
            .memory_cost_kib(env::CONF.auth_string_hash_mem_cost_kib)
            .threads(env::CONF.auth_string_hash_threads)
            .secret((&env::CONF.auth_string_hash_key).into())
            .hash(&recovery_key_data_for_recovery.new_recovery_key_auth_hash);
        let result = hash_result.map(|h| h.to_string());
        sender_recovery
            .send(result)
            .expect("Failed to send recovery hash result");
    });

    let (rehashed_auth_string_result, rehashed_recovery_key_auth_hash_result) =
        futures::join!(receiver_auth, receiver_recovery);

    let rehashed_auth_string = match rehashed_auth_string_result? {
        Ok(s) => s,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to hash new auth string",
            )));
        }
    };
    let rehashed_recovery_key_auth_hash = match rehashed_recovery_key_auth_hash_result? {
        Ok(s) => s,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to hash recovery key auth hash",
            )));
        }
    };

    let recovery_key_data_for_db = Arc::clone(&recovery_key_data);
    let save_result = web::block(move || {
        let auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.update_recovery_key_and_auth_string_and_email(
            &recovery_key_data_for_db.user_email,
            recovery_key_data_for_db.new_user_email.as_deref(),
            &rehashed_auth_string,
            &recovery_key_data_for_db.new_auth_string_hash_salt,
            recovery_key_data_for_db.new_auth_string_hash_mem_cost_kib,
            recovery_key_data_for_db.new_auth_string_hash_threads,
            recovery_key_data_for_db.new_auth_string_hash_iterations,
            &recovery_key_data_for_db.new_recovery_key_hash_salt_for_encryption,
            &recovery_key_data_for_db.new_recovery_key_hash_salt_for_recovery_auth,
            recovery_key_data_for_db.new_recovery_key_hash_mem_cost_kib,
            recovery_key_data_for_db.new_recovery_key_hash_threads,
            recovery_key_data_for_db.new_recovery_key_hash_iterations,
            &rehashed_recovery_key_auth_hash,
            &recovery_key_data_for_db.encryption_key_encrypted_with_new_password,
            &recovery_key_data_for_db.encryption_key_encrypted_with_new_recovery_key,
        )
    })
    .await;

    match save_result {
        Ok(Ok(())) => Ok(HttpResponse::Ok().finish()),
        _ => Err(HttpErrorResponse::InternalError(String::from(
            "Failed to update user data during recovery",
        ))),
    }
}

pub async fn logout(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    refresh_token: UnverifiedToken<Refresh, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let refresh_token_claims = refresh_token.verify()?;

    if refresh_token_claims.user_id != user_access_token.0.user_id {
        return Err(HttpErrorResponse::UserDisallowed(String::from(
            "Refresh token does not belong to user.",
        )));
    }

    match web::block(move || {
        let auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.blacklist_token(&refresh_token.0.signature, refresh_token_claims.expiration)
    })
    .await?
    {
        Ok(_) => (),
        Err(DaoError::QueryFailure(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ))) => {
            return Err(HttpErrorResponse::ConflictWithExisting(String::from(
                "Token already on blacklist",
            )));
        }
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to blacklist token",
            )));
        }
    }

    Ok(HttpResponse::Ok().finish())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use actix_web::App;

    use entries_common::messages::{ErrorType, NewUser, ServerErrorResponse};
    use entries_common::models::{user::User, user_otp::UserOtp};
    use entries_common::schema::{signin_nonces, user_otps, users};
    use entries_common::threadrand::SecureRng;

    use actix_protobuf::ProtoBufConfig;
    use actix_web::body::to_bytes;
    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::web::Data;
    use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
    use entries_common::token::Token;
    use prost::Message;
    use std::str::FromStr;
    use tokio::time::sleep;
    use uuid::Uuid;

    use crate::handlers::test_utils::{self, gen_bytes};
    use crate::middleware::Limiter;
    use crate::services::api::RouteLimiters;

    #[actix_web::test]
    async fn test_signin_limiter() {
        let limiter =
            SigninLimiter::new_for_tests(2, Duration::from_millis(5), Duration::from_millis(8));

        // Choose emails that map to the same shard:
        // 'a' (0x61 => low nibble 1) XOR second char low nibble 1 => shard 0.
        let email = "aa@example.com".to_string();
        let other_email_same_shard = "a1@example.com".to_string();
        let clear_trigger_email_same_shard = "aq@example.com".to_string();

        assert!(limiter.allow_attempt(email.clone()).await);
        assert!(limiter.allow_attempt(email.clone()).await);
        assert!(!limiter.allow_attempt(email.clone()).await);

        // Different key, same shard should not affect the original key
        assert!(limiter.allow_attempt(other_email_same_shard.clone()).await);

        sleep(Duration::from_millis(5)).await;

        // Period has expired, so the original key should be allowed again
        assert!(limiter.allow_attempt(email.clone()).await);
        assert!(limiter.allow_attempt(email.clone()).await);
        assert!(!limiter.allow_attempt(email.clone()).await);

        sleep(Duration::from_millis(1)).await;

        // Period has not expired
        assert!(!limiter.allow_attempt(email.clone()).await);

        sleep(Duration::from_millis(3)).await;

        // This request should trigger a clear (new key, same shard, sufficient time since last_clear)
        assert!(limiter.allow_attempt(clear_trigger_email_same_shard).await);

        // Table has been cleared, so the original key should be allowed again even though the period
        // since the last reset has not necessarily fully elapsed.
        assert!(limiter.allow_attempt(email.clone()).await);
        assert!(limiter.allow_attempt(email.clone()).await);
        assert!(!limiter.allow_attempt(email).await);
    }

    #[actix_web::test]
    async fn test_obtain_nonce_and_auth_string_params() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, _, _, _) = test_utils::create_user().await;

        let salt = gen_bytes(16);
        let nonce = i32::MAX;

        diesel::update(users::table.find(user.id))
            .set((
                users::auth_string_hash_salt.eq(&salt),
                users::auth_string_hash_mem_cost_kib.eq(10),
                users::auth_string_hash_threads.eq(10),
                users::auth_string_hash_iterations.eq(10),
            ))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        diesel::update(signin_nonces::table.find(&user.email))
            .set(signin_nonces::nonce.eq(nonce))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        // Real user
        let req = TestRequest::get()
            .uri(&format!(
                "/api/auth/nonce_and_auth_string_params?email={}",
                user.email
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = SigninNonceAndHashParams::decode(resp_body).unwrap();

        assert_eq!(resp_body.nonce, nonce);
        assert_eq!(resp_body.auth_string_hash_salt, salt);
        assert_eq!(resp_body.auth_string_hash_mem_cost_kib, 10);
        assert_eq!(resp_body.auth_string_hash_threads, 10);
        assert_eq!(resp_body.auth_string_hash_iterations, 10);

        // Fake user
        let req = TestRequest::get()
            .uri("/api/auth/nonce_and_auth_string_params?email=fake@fakerson.com")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = SigninNonceAndHashParams::decode(resp_body).unwrap();

        let first_salt = resp_body.auth_string_hash_salt.clone();
        let first_nonce = resp_body.nonce;

        assert_eq!(
            resp_body.auth_string_hash_mem_cost_kib,
            env::CONF.client_auth_string_hash_mem_cost_kib
        );
        assert_eq!(
            resp_body.auth_string_hash_threads,
            env::CONF.client_auth_string_hash_threads
        );
        assert_eq!(
            resp_body.auth_string_hash_iterations,
            env::CONF.client_auth_string_hash_iterations
        );

        // Should be the same nonce and salt, even for a fake user
        let req = TestRequest::get()
            .uri("/api/auth/nonce_and_auth_string_params?email=fake@fakerson.com")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = SigninNonceAndHashParams::decode(resp_body).unwrap();

        assert_eq!(resp_body.nonce, first_nonce);
        assert_eq!(resp_body.auth_string_hash_salt, first_salt);
        assert_eq!(
            resp_body.auth_string_hash_mem_cost_kib,
            env::CONF.client_auth_string_hash_mem_cost_kib
        );
        assert_eq!(
            resp_body.auth_string_hash_threads,
            env::CONF.client_auth_string_hash_threads
        );
        assert_eq!(
            resp_body.auth_string_hash_iterations,
            env::CONF.client_auth_string_hash_iterations
        );

        // Different fake email should have a different nonce and salt
        let req = TestRequest::get()
            .uri("/api/auth/nonce_and_auth_string_params?email=anotherfake@fake.com")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = SigninNonceAndHashParams::decode(resp_body).unwrap();

        assert_ne!(resp_body.nonce, first_nonce);
        assert_ne!(resp_body.auth_string_hash_salt, first_salt);
        assert_eq!(
            resp_body.auth_string_hash_mem_cost_kib,
            env::CONF.client_auth_string_hash_mem_cost_kib
        );
        assert_eq!(
            resp_body.auth_string_hash_threads,
            env::CONF.client_auth_string_hash_threads
        );
        assert_eq!(
            resp_body.auth_string_hash_iterations,
            env::CONF.client_auth_string_hash_iterations
        );
    }

    #[actix_web::test]
    async fn test_sign_in() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let user_number = SecureRng::next_u128();

        let password = format!("password{user_number}");
        let auth_string = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(password.as_bytes())
            .unwrap();

        let public_key_id = Uuid::now_v7();
        let new_user = NewUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: Vec::from(auth_string.as_bytes()),

            auth_string_hash_salt: Vec::from(auth_string.salt_bytes()),
            auth_string_hash_mem_cost_kib: 128,
            auth_string_hash_threads: 1,
            auth_string_hash_iterations: 2,

            password_encryption_key_salt: gen_bytes(10),
            password_encryption_key_mem_cost_kib: 1024,
            password_encryption_key_threads: 1,
            password_encryption_key_iterations: 1,

            recovery_key_hash_salt_for_encryption: gen_bytes(16),
            recovery_key_hash_salt_for_recovery_auth: gen_bytes(16),
            recovery_key_hash_mem_cost_kib: 1024,
            recovery_key_hash_threads: 1,
            recovery_key_hash_iterations: 1,

            recovery_key_auth_hash: gen_bytes(32),

            encryption_key_encrypted_with_password: gen_bytes(10),
            encryption_key_encrypted_with_recovery_key: gen_bytes(10),

            public_key_id: public_key_id.into(),
            public_key: gen_bytes(10),

            preferences_encrypted: gen_bytes(10),
            preferences_version_nonce: SecureRng::next_i64(),
            user_keystore_encrypted: gen_bytes(10),
            user_keystore_version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_user.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        dsl::update(users::table.filter(users::email.eq(&new_user.email)))
            .set(users::is_verified.eq(true))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let req = TestRequest::get()
            .uri(&format!(
                "/api/auth/nonce_and_auth_string_params?email={}",
                &new_user.email
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = SigninNonceAndHashParams::decode(resp_body).unwrap();

        let mut credentials = CredentialPair {
            email: new_user.email.clone(),
            auth_string: Vec::from(auth_string.as_bytes()),
            nonce: resp_body.nonce,
        };

        let byte = credentials.auth_string.pop().unwrap();
        credentials.auth_string.push(byte.wrapping_add(1));

        let req = TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(credentials.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = TestRequest::get()
            .uri(&format!(
                "/api/auth/nonce_and_auth_string_params?email={}",
                &new_user.email
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = SigninNonceAndHashParams::decode(resp_body).unwrap();

        let credentials = CredentialPair {
            email: new_user.email.clone(),
            auth_string: Vec::from(auth_string.as_bytes()),
            nonce: resp_body.nonce,
        };

        let req = TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(credentials.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let signin_token = SigninToken::decode(resp_body).unwrap();

        let signin_token = AuthToken::decode(&signin_token.value).unwrap();
        let token_type = signin_token.claims.token_type;

        assert!(matches!(token_type, AuthTokenType::SignIn));

        let claims = signin_token.claims;

        assert_eq!(claims.user_email, new_user.email);
        assert!(
            claims.expiration
                > (SystemTime::now() + Duration::from_secs(60))
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );

        // User shouldn't be able to sign in again until they verify their email
        dsl::update(users::table.filter(users::email.eq(&new_user.email)))
            .set(users::is_verified.eq(false))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let req = TestRequest::get()
            .uri(&format!(
                "/api/auth/nonce_and_auth_string_params?email={}",
                &new_user.email
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = SigninNonceAndHashParams::decode(resp_body).unwrap();

        let credentials = CredentialPair {
            email: new_user.email,
            auth_string: Vec::from(auth_string.as_bytes()),
            nonce: resp_body.nonce,
        };

        let req = TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(credentials.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_err.err_type, ErrorType::PendingAction as i32);
    }

    #[actix_web::test]
    async fn test_verify_otp_for_signin() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let user_number = SecureRng::next_u128();

        let password = format!("password{user_number}");
        let auth_string = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(password.as_bytes())
            .unwrap();

        let public_key_id = Uuid::now_v7();
        let new_user = NewUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: Vec::from(auth_string.as_bytes()),

            auth_string_hash_salt: Vec::from(auth_string.salt_bytes()),
            auth_string_hash_mem_cost_kib: 128,
            auth_string_hash_threads: 1,
            auth_string_hash_iterations: 2,

            password_encryption_key_salt: gen_bytes(10),
            password_encryption_key_mem_cost_kib: 1024,
            password_encryption_key_threads: 1,
            password_encryption_key_iterations: 1,

            recovery_key_hash_salt_for_encryption: gen_bytes(16),
            recovery_key_hash_salt_for_recovery_auth: gen_bytes(16),
            recovery_key_hash_mem_cost_kib: 1024,
            recovery_key_hash_threads: 1,
            recovery_key_hash_iterations: 1,

            recovery_key_auth_hash: gen_bytes(32),

            encryption_key_encrypted_with_password: gen_bytes(10),
            encryption_key_encrypted_with_recovery_key: gen_bytes(10),

            public_key_id: public_key_id.into(),
            public_key: gen_bytes(10),

            preferences_encrypted: gen_bytes(10),
            preferences_version_nonce: SecureRng::next_i64(),
            user_keystore_encrypted: gen_bytes(10),
            user_keystore_version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_user.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        dsl::update(users::table.filter(users::email.eq(&new_user.email)))
            .set(users::is_verified.eq(true))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let req = TestRequest::get()
            .uri(&format!(
                "/api/auth/nonce_and_auth_string_params?email={}",
                &new_user.email
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = SigninNonceAndHashParams::decode(resp_body).unwrap();

        let credentials = CredentialPair {
            email: new_user.email.clone(),
            auth_string: Vec::from(auth_string.as_bytes()),
            nonce: resp_body.nonce,
        };

        let req = TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(credentials.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let signin_token = SigninToken::decode(resp_body).unwrap();

        let otp = user_otps::table
            .find(&new_user.email)
            .get_result::<UserOtp>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let otp_msg = OtpMessage {
            value: otp.otp.clone(),
        };

        let req = TestRequest::post()
            .uri("/api/auth/otp/verify")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(otp_msg.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let bad_signin_token = "thisisabadtoken";

        let req = TestRequest::post()
            .uri("/api/auth/otp/verify")
            .insert_header(("Content-Type", "application/protobuf"))
            .insert_header(("SignInToken", bad_signin_token))
            .set_payload(otp_msg.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = TestRequest::post()
            .uri("/api/auth/otp/verify")
            .insert_header(("Content-Type", "application/protobuf"))
            .insert_header(("SignInToken", signin_token.value.clone()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let mut bad_otp_msg = otp_msg.clone();
        let letter = bad_otp_msg.value.pop().unwrap();
        bad_otp_msg
            .value
            .push(if letter == 'E' { 'F' } else { 'E' });

        let req = TestRequest::post()
            .uri("/api/auth/otp/verify")
            .insert_header(("Content-Type", "application/protobuf"))
            .insert_header(("SignInToken", signin_token.value.clone()))
            .set_payload(bad_otp_msg.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = TestRequest::post()
            .uri("/api/auth/otp/verify")
            .insert_header(("Content-Type", "application/protobuf"))
            .insert_header(("SignInToken", signin_token.value))
            .set_payload(otp_msg.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let authenticated_session = AuthenticatedSession::decode(resp_body).unwrap();

        let access_token = AuthToken::decode(&authenticated_session.tokens.access_token).unwrap();
        let refresh_token = AuthToken::decode(&authenticated_session.tokens.refresh_token).unwrap();

        assert!(matches!(
            access_token.claims.token_type,
            AuthTokenType::Access
        ));
        assert!(matches!(
            refresh_token.claims.token_type,
            AuthTokenType::Refresh
        ));

        assert!(access_token.verify(&env::CONF.token_signing_key).is_ok());
        assert!(refresh_token.verify(&env::CONF.token_signing_key).is_ok());

        assert_eq!(
            authenticated_session.preferences_encrypted,
            new_user.preferences_encrypted
        );
        assert_eq!(
            authenticated_session.preferences_version_nonce,
            new_user.preferences_version_nonce
        );
        assert_eq!(
            authenticated_session.user_keystore_encrypted,
            new_user.user_keystore_encrypted
        );
        assert_eq!(
            authenticated_session.user_keystore_version_nonce,
            new_user.user_keystore_version_nonce
        );
        assert_eq!(
            authenticated_session.password_encryption_key_salt,
            new_user.password_encryption_key_salt
        );
        assert_eq!(
            authenticated_session.password_encryption_key_mem_cost_kib,
            new_user.password_encryption_key_mem_cost_kib
        );
        assert_eq!(
            authenticated_session.password_encryption_key_threads,
            new_user.password_encryption_key_threads
        );
        assert_eq!(
            authenticated_session.password_encryption_key_iterations,
            new_user.password_encryption_key_iterations
        );
        assert_eq!(
            authenticated_session.encryption_key_encrypted_with_password,
            new_user.encryption_key_encrypted_with_password
        );
    }

    #[actix_rt::test]
    async fn test_obtain_otp() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, _, _) = test_utils::create_user().await;

        let old_otp = user_otps::table
            .find(&user.email)
            .get_result::<UserOtp>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let req = TestRequest::get()
            .uri("/api/auth/otp")
            .insert_header(("AccessToken", access_token))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();

        let new_otp = user_otps::table
            .find(&user.email)
            .get_result::<UserOtp>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let resp_body = String::from_utf8_lossy(&resp_body);
        assert!(!resp_body.contains(&new_otp.otp));
        assert!(old_otp.otp != new_otp.otp);
    }

    #[actix_web::test]
    #[ignore]
    async fn test_recover_with_recovery_key_success() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, _, _, _) = test_utils::create_user().await;

        // Simulate client-side hash (arbitrary params that the client uses)
        let recovery_key = format!("recovery_key_{}", SecureRng::next_u128());
        let client_hash = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(recovery_key.as_bytes())
            .unwrap();

        // Simulate server-side rehash (configured params)
        let server_hash = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.auth_string_hash_salt_length)
            .hash_length(env::CONF.auth_string_hash_length)
            .iterations(env::CONF.auth_string_hash_iterations)
            .memory_cost_kib(env::CONF.auth_string_hash_mem_cost_kib)
            .threads(env::CONF.auth_string_hash_threads)
            .secret((&env::CONF.auth_string_hash_key).into())
            .hash(client_hash.as_bytes())
            .unwrap();

        // Update user's recovery key hash in database
        diesel::update(users::table.find(user.id))
            .set(
                users::recovery_key_auth_hash_rehashed_with_auth_string_params
                    .eq(server_hash.to_string()),
            )
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        // Create new password and recovery key
        let new_password = format!("new_password_{}", SecureRng::next_u128());
        let new_recovery_key = format!("new_recovery_key_{}", SecureRng::next_u128());

        let new_auth_string = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(new_password.as_bytes())
            .unwrap();

        let new_recovery_key_auth_hash = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(new_recovery_key.as_bytes())
            .unwrap();

        let recovery_key_data = RecoveryKeyAuthAndPasswordUpdate {
            recovery_key_hash_for_recovery_auth: Vec::from(client_hash.as_bytes()),
            user_email: user.email.clone(),
            new_user_email: None,
            new_auth_string: Vec::from(new_auth_string.as_bytes()),
            new_auth_string_hash_salt: Vec::from(new_auth_string.salt_bytes()),
            new_auth_string_hash_mem_cost_kib: 128,
            new_auth_string_hash_threads: 1,
            new_auth_string_hash_iterations: 2,
            new_recovery_key_hash_salt_for_encryption: gen_bytes(16),
            new_recovery_key_hash_salt_for_recovery_auth: Vec::from(
                new_recovery_key_auth_hash.salt_bytes(),
            ),
            new_recovery_key_hash_mem_cost_kib: 128,
            new_recovery_key_hash_threads: 1,
            new_recovery_key_hash_iterations: 2,
            new_recovery_key_auth_hash: Vec::from(new_recovery_key_auth_hash.as_bytes()),
            encryption_key_encrypted_with_new_password: gen_bytes(48),
            encryption_key_encrypted_with_new_recovery_key: gen_bytes(48),
        };

        let req = TestRequest::post()
            .uri("/api/auth/recover_with_recovery_key")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(recovery_key_data.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        // Verify the user data was updated in the database
        let updated_user = users::table
            .find(user.id)
            .get_result::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        // Check that the new auth string hash can be verified with the new password
        assert!(argon2_kdf::Hash::from_str(&updated_user.auth_string_hash)
            .unwrap()
            .verify_with_secret(
                new_auth_string.as_bytes(),
                (&env::CONF.auth_string_hash_key).into()
            ));

        // Check that the new recovery key hash can be verified with the new recovery key
        assert!(argon2_kdf::Hash::from_str(
            &updated_user.recovery_key_auth_hash_rehashed_with_auth_string_params
        )
        .unwrap()
        .verify_with_secret(
            new_recovery_key_auth_hash.as_bytes(),
            (&env::CONF.auth_string_hash_key).into()
        ));
    }

    #[actix_web::test]
    #[ignore]
    async fn test_recover_with_recovery_key_with_email_change() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, _, _, _) = test_utils::create_user().await;

        // Simulate client-side hash (arbitrary params that the client uses)
        let recovery_key = format!("recovery_key_{}", SecureRng::next_u128());
        let client_hash = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(recovery_key.as_bytes())
            .unwrap();

        // Simulate server-side rehash (configured params)
        let server_hash = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.auth_string_hash_salt_length)
            .hash_length(env::CONF.auth_string_hash_length)
            .iterations(env::CONF.auth_string_hash_iterations)
            .memory_cost_kib(env::CONF.auth_string_hash_mem_cost_kib)
            .threads(env::CONF.auth_string_hash_threads)
            .secret((&env::CONF.auth_string_hash_key).into())
            .hash(client_hash.as_bytes())
            .unwrap();

        // Update user's recovery key hash in database
        diesel::update(users::table.find(user.id))
            .set(
                users::recovery_key_auth_hash_rehashed_with_auth_string_params
                    .eq(server_hash.to_string()),
            )
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_email = format!("new_email_{}@test.com", SecureRng::next_u128());
        let new_password = format!("new_password_{}", SecureRng::next_u128());
        let new_recovery_key = format!("new_recovery_key_{}", SecureRng::next_u128());

        let new_auth_string = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(new_password.as_bytes())
            .unwrap();

        let new_recovery_key_auth_hash = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(new_recovery_key.as_bytes())
            .unwrap();

        let recovery_key_data = RecoveryKeyAuthAndPasswordUpdate {
            recovery_key_hash_for_recovery_auth: Vec::from(client_hash.as_bytes()),
            user_email: user.email.clone(),
            new_user_email: Some(new_email.clone()),
            new_auth_string: Vec::from(new_auth_string.as_bytes()),
            new_auth_string_hash_salt: Vec::from(new_auth_string.salt_bytes()),
            new_auth_string_hash_mem_cost_kib: 128,
            new_auth_string_hash_threads: 1,
            new_auth_string_hash_iterations: 2,
            new_recovery_key_hash_salt_for_encryption: gen_bytes(16),
            new_recovery_key_hash_salt_for_recovery_auth: Vec::from(
                new_recovery_key_auth_hash.salt_bytes(),
            ),
            new_recovery_key_hash_mem_cost_kib: 128,
            new_recovery_key_hash_threads: 1,
            new_recovery_key_hash_iterations: 2,
            new_recovery_key_auth_hash: Vec::from(new_recovery_key_auth_hash.as_bytes()),
            encryption_key_encrypted_with_new_password: gen_bytes(48),
            encryption_key_encrypted_with_new_recovery_key: gen_bytes(48),
        };

        let req = TestRequest::post()
            .uri("/api/auth/recover_with_recovery_key")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(recovery_key_data.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        // Verify the user email was updated
        let updated_user = users::table
            .find(user.id)
            .get_result::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(updated_user.email, new_email);
    }

    #[actix_web::test]
    #[ignore]
    async fn test_recover_with_recovery_key_fails_with_invalid_recovery_key() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, _, _, _) = test_utils::create_user().await;

        // Simulate client-side hash (arbitrary params that the client uses)
        let recovery_key = format!("recovery_key_{}", SecureRng::next_u128());
        let client_hash = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(recovery_key.as_bytes())
            .unwrap();

        // Simulate server-side rehash (configured params)
        let server_hash = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.auth_string_hash_salt_length)
            .hash_length(env::CONF.auth_string_hash_length)
            .iterations(env::CONF.auth_string_hash_iterations)
            .memory_cost_kib(env::CONF.auth_string_hash_mem_cost_kib)
            .threads(env::CONF.auth_string_hash_threads)
            .secret((&env::CONF.auth_string_hash_key).into())
            .hash(client_hash.as_bytes())
            .unwrap();

        // Update user's recovery key hash in database
        diesel::update(users::table.find(user.id))
            .set(
                users::recovery_key_auth_hash_rehashed_with_auth_string_params
                    .eq(server_hash.to_string()),
            )
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_password = format!("new_password_{}", SecureRng::next_u128());
        let new_recovery_key = format!("new_recovery_key_{}", SecureRng::next_u128());

        let new_auth_string = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(new_password.as_bytes())
            .unwrap();

        let new_recovery_key_auth_hash = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(new_recovery_key.as_bytes())
            .unwrap();

        // Use wrong recovery key hash
        let wrong_recovery_key_hash = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.auth_string_hash_salt_length)
            .hash_length(env::CONF.auth_string_hash_length)
            .iterations(env::CONF.auth_string_hash_iterations)
            .memory_cost_kib(env::CONF.auth_string_hash_mem_cost_kib)
            .threads(env::CONF.auth_string_hash_threads)
            .secret((&env::CONF.auth_string_hash_key).into())
            .hash("wrong_recovery_key".as_bytes())
            .unwrap();

        let recovery_key_data = RecoveryKeyAuthAndPasswordUpdate {
            recovery_key_hash_for_recovery_auth: Vec::from(wrong_recovery_key_hash.as_bytes()),
            user_email: user.email.clone(),
            new_user_email: None,
            new_auth_string: Vec::from(new_auth_string.as_bytes()),
            new_auth_string_hash_salt: Vec::from(new_auth_string.salt_bytes()),
            new_auth_string_hash_mem_cost_kib: 128,
            new_auth_string_hash_threads: 1,
            new_auth_string_hash_iterations: 2,
            new_recovery_key_hash_salt_for_encryption: gen_bytes(16),
            new_recovery_key_hash_salt_for_recovery_auth: Vec::from(
                new_recovery_key_auth_hash.salt_bytes(),
            ),
            new_recovery_key_hash_mem_cost_kib: 128,
            new_recovery_key_hash_threads: 1,
            new_recovery_key_hash_iterations: 2,
            new_recovery_key_auth_hash: Vec::from(new_recovery_key_auth_hash.as_bytes()),
            encryption_key_encrypted_with_new_password: gen_bytes(48),
            encryption_key_encrypted_with_new_recovery_key: gen_bytes(48),
        };

        let req = TestRequest::post()
            .uri("/api/auth/recover_with_recovery_key")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(recovery_key_data.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_err.err_type, ErrorType::IncorrectCredential as i32);
    }

    #[actix_web::test]
    async fn test_recover_with_recovery_key_fails_with_invalid_email() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let recovery_key_data = RecoveryKeyAuthAndPasswordUpdate {
            recovery_key_hash_for_recovery_auth: gen_bytes(32),
            user_email: "invalid_email".to_string(),
            new_user_email: None,
            new_auth_string: gen_bytes(32),
            new_auth_string_hash_salt: gen_bytes(16),
            new_auth_string_hash_mem_cost_kib: 128,
            new_auth_string_hash_threads: 1,
            new_auth_string_hash_iterations: 2,
            new_recovery_key_hash_salt_for_encryption: gen_bytes(16),
            new_recovery_key_hash_salt_for_recovery_auth: gen_bytes(16),
            new_recovery_key_hash_mem_cost_kib: 128,
            new_recovery_key_hash_threads: 1,
            new_recovery_key_hash_iterations: 2,
            new_recovery_key_auth_hash: gen_bytes(32),
            encryption_key_encrypted_with_new_password: gen_bytes(48),
            encryption_key_encrypted_with_new_recovery_key: gen_bytes(48),
        };

        let req = TestRequest::post()
            .uri("/api/auth/recover_with_recovery_key")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(recovery_key_data.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_err.err_type, ErrorType::IncorrectlyFormed as i32);
    }

    #[actix_web::test]
    async fn test_recover_with_recovery_key_fails_with_invalid_new_email() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, _, _, _) = test_utils::create_user().await;

        let recovery_key_data = RecoveryKeyAuthAndPasswordUpdate {
            recovery_key_hash_for_recovery_auth: gen_bytes(32),
            user_email: user.email.clone(),
            new_user_email: Some("invalid_new_email".to_string()),
            new_auth_string: gen_bytes(32),
            new_auth_string_hash_salt: gen_bytes(16),
            new_auth_string_hash_mem_cost_kib: 128,
            new_auth_string_hash_threads: 1,
            new_auth_string_hash_iterations: 2,
            new_recovery_key_hash_salt_for_encryption: gen_bytes(16),
            new_recovery_key_hash_salt_for_recovery_auth: gen_bytes(16),
            new_recovery_key_hash_mem_cost_kib: 128,
            new_recovery_key_hash_threads: 1,
            new_recovery_key_hash_iterations: 2,
            new_recovery_key_auth_hash: gen_bytes(32),
            encryption_key_encrypted_with_new_password: gen_bytes(48),
            encryption_key_encrypted_with_new_recovery_key: gen_bytes(48),
        };

        let req = TestRequest::post()
            .uri("/api/auth/recover_with_recovery_key")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(recovery_key_data.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_err.err_type, ErrorType::IncorrectlyFormed as i32);
    }

    #[actix_web::test]
    async fn test_recover_with_recovery_key_fails_with_nonexistent_user() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let recovery_key_data = RecoveryKeyAuthAndPasswordUpdate {
            recovery_key_hash_for_recovery_auth: gen_bytes(32),
            user_email: "nonexistent@test.com".to_string(),
            new_user_email: None,
            new_auth_string: gen_bytes(32),
            new_auth_string_hash_salt: gen_bytes(16),
            new_auth_string_hash_mem_cost_kib: 128,
            new_auth_string_hash_threads: 1,
            new_auth_string_hash_iterations: 2,
            new_recovery_key_hash_salt_for_encryption: gen_bytes(16),
            new_recovery_key_hash_salt_for_recovery_auth: gen_bytes(16),
            new_recovery_key_hash_mem_cost_kib: 128,
            new_recovery_key_hash_threads: 1,
            new_recovery_key_hash_iterations: 2,
            new_recovery_key_auth_hash: gen_bytes(32),
            encryption_key_encrypted_with_new_password: gen_bytes(48),
            encryption_key_encrypted_with_new_recovery_key: gen_bytes(48),
        };

        let req = TestRequest::post()
            .uri("/api/auth/recover_with_recovery_key")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(recovery_key_data.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_err.err_type, ErrorType::IncorrectCredential as i32);
    }

    #[actix_web::test]
    #[ignore]
    async fn test_recover_with_recovery_key_fails_with_large_input() {
        let mut protobuf_config = ProtoBufConfig::default();
        protobuf_config.limit(env::CONF.protobuf_max_size);

        let route_limiters = RouteLimiters {
            recovery: Limiter::new(100, Duration::from_secs(1), Duration::from_secs(10)),
            ..Default::default()
        };

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(protobuf_config)
                .configure(|cfg| crate::services::api::configure(cfg, route_limiters)),
        )
        .await;

        let (user, _, _, _) = test_utils::create_user().await;

        let recovery_key_data = RecoveryKeyAuthAndPasswordUpdate {
            recovery_key_hash_for_recovery_auth: gen_bytes(32),
            user_email: user.email.clone(),
            new_user_email: None,
            new_auth_string: gen_bytes(32),
            new_auth_string_hash_salt: gen_bytes(16),
            new_auth_string_hash_mem_cost_kib: 1024,
            new_auth_string_hash_threads: 1,
            new_auth_string_hash_iterations: 2,
            new_recovery_key_hash_salt_for_encryption: gen_bytes(16),
            new_recovery_key_hash_salt_for_recovery_auth: gen_bytes(16),
            new_recovery_key_hash_mem_cost_kib: 1024,
            new_recovery_key_hash_threads: 1,
            new_recovery_key_hash_iterations: 2,
            new_recovery_key_auth_hash: gen_bytes(32),
            encryption_key_encrypted_with_new_password: gen_bytes(48),
            encryption_key_encrypted_with_new_recovery_key: gen_bytes(48),
        };

        let mut temp = recovery_key_data.clone();
        temp.new_auth_string = vec![0; env::CONF.max_auth_string_length + 1];
        let req = TestRequest::post()
            .uri("/api/auth/recover_with_recovery_key")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::IncorrectlyFormed as i32);

        let mut temp = recovery_key_data.clone();
        temp.new_auth_string_hash_salt = vec![0; env::CONF.max_encryption_key_size + 1];
        let req = TestRequest::post()
            .uri("/api/auth/recover_with_recovery_key")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let mut temp = recovery_key_data.clone();
        temp.new_recovery_key_hash_salt_for_encryption =
            vec![0; env::CONF.max_encryption_key_size + 1];
        let req = TestRequest::post()
            .uri("/api/auth/recover_with_recovery_key")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let mut temp = recovery_key_data.clone();
        temp.new_recovery_key_hash_salt_for_recovery_auth =
            vec![0; env::CONF.max_encryption_key_size + 1];
        let req = TestRequest::post()
            .uri("/api/auth/recover_with_recovery_key")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let mut temp = recovery_key_data.clone();
        temp.new_recovery_key_auth_hash = vec![0; env::CONF.max_encryption_key_size + 1];
        let req = TestRequest::post()
            .uri("/api/auth/recover_with_recovery_key")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let mut temp = recovery_key_data.clone();
        temp.encryption_key_encrypted_with_new_password =
            vec![0; env::CONF.max_encryption_key_size + 1];
        let req = TestRequest::post()
            .uri("/api/auth/recover_with_recovery_key")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let mut temp = recovery_key_data.clone();
        temp.encryption_key_encrypted_with_new_recovery_key =
            vec![0; env::CONF.max_encryption_key_size + 1];
        let req = TestRequest::post()
            .uri("/api/auth/recover_with_recovery_key")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_web::test]
    async fn test_sign_in_fails_for_unverified_user() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let user_number = SecureRng::next_u128();

        let password = format!("password{user_number}");
        let auth_string = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(password.as_bytes())
            .unwrap();

        let public_key_id = Uuid::now_v7();
        let new_user = NewUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: Vec::from(auth_string.as_bytes()),

            auth_string_hash_salt: Vec::from(auth_string.salt_bytes()),
            auth_string_hash_mem_cost_kib: 128,
            auth_string_hash_threads: 1,
            auth_string_hash_iterations: 2,

            password_encryption_key_salt: gen_bytes(10),
            password_encryption_key_mem_cost_kib: 1024,
            password_encryption_key_threads: 1,
            password_encryption_key_iterations: 1,

            recovery_key_hash_salt_for_encryption: gen_bytes(16),
            recovery_key_hash_salt_for_recovery_auth: gen_bytes(16),
            recovery_key_hash_mem_cost_kib: 1024,
            recovery_key_hash_threads: 1,
            recovery_key_hash_iterations: 1,

            recovery_key_auth_hash: gen_bytes(32),

            encryption_key_encrypted_with_password: gen_bytes(10),
            encryption_key_encrypted_with_recovery_key: gen_bytes(10),

            public_key_id: public_key_id.into(),
            public_key: gen_bytes(10),

            preferences_encrypted: gen_bytes(10),
            preferences_version_nonce: SecureRng::next_i64(),
            user_keystore_encrypted: gen_bytes(10),
            user_keystore_version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_user.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        // Ensure user is not verified (this should be the default state)
        let user = users::table
            .filter(users::email.eq(&new_user.email))
            .get_result::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();
        assert!(!user.is_verified);

        let req = TestRequest::get()
            .uri(&format!(
                "/api/auth/nonce_and_auth_string_params?email={}",
                &new_user.email
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = SigninNonceAndHashParams::decode(resp_body).unwrap();

        let credentials = CredentialPair {
            email: new_user.email,
            auth_string: Vec::from(auth_string.as_bytes()),
            nonce: resp_body.nonce,
        };

        let req = TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(credentials.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_err.err_type, ErrorType::PendingAction as i32);
        assert!(resp_err
            .err_message
            .contains("A new verification email has been sent"));

        // Verify that a token created with the user's creation timestamp + lifetime would be valid
        // This confirms the token expiration is based on creation timestamp, not current time
        let user_creation_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: (user.created_timestamp + env::CONF.user_creation_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .expect("System time should be after Unix Epoch")
                .as_secs(),
            token_type: AuthTokenType::UserCreation,
        };

        let user_creation_token =
            AuthToken::sign_new(user_creation_token_claims, &env::CONF.token_signing_key);

        // Verify the token can be used to verify the user
        let req = TestRequest::get()
            .uri(&format!(
                "/api/user/verify?UserCreationToken={}",
                user_creation_token
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        // Verify user is now verified
        let verified_user = users::table
            .filter(users::email.eq(&user.email))
            .get_result::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();
        assert!(verified_user.is_verified);
    }

    #[actix_web::test]
    async fn test_sign_in_sends_verification_email_with_correct_expiration() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let user_number = SecureRng::next_u128();

        let password = format!("password{user_number}");
        let auth_string = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(password.as_bytes())
            .unwrap();

        let public_key_id = Uuid::now_v7();
        let new_user = NewUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: Vec::from(auth_string.as_bytes()),

            auth_string_hash_salt: Vec::from(auth_string.salt_bytes()),
            auth_string_hash_mem_cost_kib: 128,
            auth_string_hash_threads: 1,
            auth_string_hash_iterations: 2,

            password_encryption_key_salt: gen_bytes(10),
            password_encryption_key_mem_cost_kib: 1024,
            password_encryption_key_threads: 1,
            password_encryption_key_iterations: 1,

            recovery_key_hash_salt_for_encryption: gen_bytes(16),
            recovery_key_hash_salt_for_recovery_auth: gen_bytes(16),
            recovery_key_hash_mem_cost_kib: 1024,
            recovery_key_hash_threads: 1,
            recovery_key_hash_iterations: 1,

            recovery_key_auth_hash: gen_bytes(32),

            encryption_key_encrypted_with_password: gen_bytes(10),
            encryption_key_encrypted_with_recovery_key: gen_bytes(10),

            public_key_id: public_key_id.into(),
            public_key: gen_bytes(10),

            preferences_encrypted: gen_bytes(10),
            preferences_version_nonce: SecureRng::next_i64(),
            user_keystore_encrypted: gen_bytes(10),
            user_keystore_version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_user.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        // Get the user and record their creation timestamp
        let user = users::table
            .filter(users::email.eq(&new_user.email))
            .get_result::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();
        assert!(!user.is_verified);

        let creation_timestamp = user.created_timestamp;
        let expected_expiration = creation_timestamp + env::CONF.user_creation_token_lifetime;

        // Wait a short time to ensure current time has advanced
        tokio::time::sleep(Duration::from_millis(100)).await;

        let req = TestRequest::get()
            .uri(&format!(
                "/api/auth/nonce_and_auth_string_params?email={}",
                &new_user.email
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = SigninNonceAndHashParams::decode(resp_body).unwrap();

        let credentials = CredentialPair {
            email: user.email.clone(),
            auth_string: Vec::from(auth_string.as_bytes()),
            nonce: resp_body.nonce,
        };

        // Attempt sign in - this should send a new verification email
        let req = TestRequest::post()
            .uri("/api/auth/sign_in")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(credentials.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Verify that the token expiration is based on creation timestamp, not current time
        // Create a token with the expected expiration (creation_timestamp + lifetime)
        let user_creation_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: expected_expiration
                .duration_since(UNIX_EPOCH)
                .expect("System time should be after Unix Epoch")
                .as_secs(),
            token_type: AuthTokenType::UserCreation,
        };

        let user_creation_token =
            AuthToken::sign_new(user_creation_token_claims, &env::CONF.token_signing_key);

        // Verify the token is valid and can be used to verify the user
        let req = TestRequest::get()
            .uri(&format!(
                "/api/user/verify?UserCreationToken={}",
                user_creation_token
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        // Verify that a token with expiration based on current time (not creation time) would be different
        // This confirms we're using creation_timestamp, not SystemTime::now()
        let now = SystemTime::now();
        let wrong_expiration = (now + env::CONF.user_creation_token_lifetime)
            .duration_since(UNIX_EPOCH)
            .expect("System time should be after Unix Epoch")
            .as_secs();

        // The expected expiration should be less than or equal to the wrong expiration
        // (since we waited after user creation, creation_timestamp + lifetime < now + lifetime)
        let expected_expiration_secs = expected_expiration
            .duration_since(UNIX_EPOCH)
            .expect("System time should be after Unix Epoch")
            .as_secs();

        assert!(
            expected_expiration_secs <= wrong_expiration,
            "Token expiration should be based on creation timestamp, not current time"
        );
    }

    #[actix_web::test]
    async fn test_recovery_key_fails_for_unverified_user() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let user_number = SecureRng::next_u128();

        let password = format!("password{user_number}");
        let auth_string = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(password.as_bytes())
            .unwrap();

        let public_key_id = Uuid::now_v7();
        let new_user = NewUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: Vec::from(auth_string.as_bytes()),

            auth_string_hash_salt: Vec::from(auth_string.salt_bytes()),
            auth_string_hash_mem_cost_kib: 128,
            auth_string_hash_threads: 1,
            auth_string_hash_iterations: 2,

            password_encryption_key_salt: gen_bytes(10),
            password_encryption_key_mem_cost_kib: 1024,
            password_encryption_key_threads: 1,
            password_encryption_key_iterations: 1,

            recovery_key_hash_salt_for_encryption: gen_bytes(16),
            recovery_key_hash_salt_for_recovery_auth: gen_bytes(16),
            recovery_key_hash_mem_cost_kib: 1024,
            recovery_key_hash_threads: 1,
            recovery_key_hash_iterations: 1,

            recovery_key_auth_hash: gen_bytes(32),

            encryption_key_encrypted_with_password: gen_bytes(10),
            encryption_key_encrypted_with_recovery_key: gen_bytes(10),

            public_key_id: public_key_id.into(),
            public_key: gen_bytes(10),

            preferences_encrypted: gen_bytes(10),
            preferences_version_nonce: SecureRng::next_i64(),
            user_keystore_encrypted: gen_bytes(10),
            user_keystore_version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_user.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        // Ensure user is not verified (this should be the default state)
        let user = users::table
            .filter(users::email.eq(&new_user.email))
            .get_result::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();
        assert!(!user.is_verified);

        // Simulate client-side hash (arbitrary params that the client uses)
        let recovery_key = format!("recovery_key_{}", SecureRng::next_u128());
        let client_hash = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(recovery_key.as_bytes())
            .unwrap();

        // Simulate server-side rehash (configured params)
        let server_hash = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.auth_string_hash_salt_length)
            .hash_length(env::CONF.auth_string_hash_length)
            .iterations(env::CONF.auth_string_hash_iterations)
            .memory_cost_kib(env::CONF.auth_string_hash_mem_cost_kib)
            .threads(env::CONF.auth_string_hash_threads)
            .secret((&env::CONF.auth_string_hash_key).into())
            .hash(client_hash.as_bytes())
            .unwrap();

        // Update user's recovery key hash in database
        diesel::update(users::table.find(user.id))
            .set(
                users::recovery_key_auth_hash_rehashed_with_auth_string_params
                    .eq(server_hash.to_string()),
            )
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        // Create new password and recovery key
        let new_password = format!("new_password_{}", SecureRng::next_u128());
        let new_recovery_key = format!("new_recovery_key_{}", SecureRng::next_u128());

        let new_auth_string = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(new_password.as_bytes())
            .unwrap();

        let new_recovery_key_auth_hash = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(new_recovery_key.as_bytes())
            .unwrap();

        let recovery_key_data = RecoveryKeyAuthAndPasswordUpdate {
            recovery_key_hash_for_recovery_auth: Vec::from(client_hash.as_bytes()),
            user_email: user.email.clone(),
            new_user_email: None,
            new_auth_string: Vec::from(new_auth_string.as_bytes()),
            new_auth_string_hash_salt: Vec::from(new_auth_string.salt_bytes()),
            new_auth_string_hash_mem_cost_kib: 128,
            new_auth_string_hash_threads: 1,
            new_auth_string_hash_iterations: 2,
            new_recovery_key_hash_salt_for_encryption: gen_bytes(16),
            new_recovery_key_hash_salt_for_recovery_auth: Vec::from(
                new_recovery_key_auth_hash.salt_bytes(),
            ),
            new_recovery_key_hash_mem_cost_kib: 128,
            new_recovery_key_hash_threads: 1,
            new_recovery_key_hash_iterations: 2,
            new_recovery_key_auth_hash: Vec::from(new_recovery_key_auth_hash.as_bytes()),
            encryption_key_encrypted_with_new_password: gen_bytes(48),
            encryption_key_encrypted_with_new_recovery_key: gen_bytes(48),
        };

        let req = TestRequest::post()
            .uri("/api/auth/recover_with_recovery_key")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(recovery_key_data.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_err.err_type, ErrorType::InvalidState as i32);
    }

    #[actix_web::test]
    async fn test_refresh_tokens_success() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, _, _, _) = test_utils::create_user().await;

        // Create a valid refresh token
        let refresh_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: (SystemTime::now() + env::CONF.refresh_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            token_type: AuthTokenType::Refresh,
        };

        let refresh_token =
            AuthToken::sign_new(refresh_token_claims.clone(), &env::CONF.token_signing_key);

        let req = TestRequest::post()
            .uri("/api/auth/token/refresh")
            .insert_header(("RefreshToken", refresh_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let token_pair = TokenPair::decode(resp_body).unwrap();

        let access_token = AuthToken::decode(&token_pair.access_token).unwrap();
        let new_refresh_token = AuthToken::decode(&token_pair.refresh_token).unwrap();

        assert!(matches!(
            access_token.claims.token_type,
            AuthTokenType::Access
        ));
        assert!(matches!(
            new_refresh_token.claims.token_type,
            AuthTokenType::Refresh
        ));
        assert!(access_token.verify(&env::CONF.token_signing_key).is_ok());
        assert!(new_refresh_token
            .verify(&env::CONF.token_signing_key)
            .is_ok());
    }

    #[actix_web::test]
    async fn test_refresh_tokens_with_expired_token() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, _, _, _) = test_utils::create_user().await;

        // Create an expired refresh token
        let refresh_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: (SystemTime::now() - Duration::from_secs(3600))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            token_type: AuthTokenType::Refresh,
        };

        let refresh_token = AuthToken::sign_new(refresh_token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::post()
            .uri("/api/auth/token/refresh")
            .insert_header(("RefreshToken", refresh_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();
        assert_eq!(resp_err.err_type, ErrorType::TokenExpired as i32);
    }

    #[actix_web::test]
    async fn test_refresh_tokens_with_blacklisted_token() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, _, _, _) = test_utils::create_user().await;

        // Create a valid refresh token
        let refresh_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: (SystemTime::now() + env::CONF.refresh_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            token_type: AuthTokenType::Refresh,
        };

        let refresh_token =
            AuthToken::sign_new(refresh_token_claims.clone(), &env::CONF.token_signing_key);

        // Blacklist the token first
        let auth_dao = db::auth::Dao::new(&env::testing::DB_THREAD_POOL);
        let decoded_refresh_token = AuthToken::decode(&refresh_token).unwrap();
        let refresh_token_claims_clone = refresh_token_claims.clone();
        auth_dao
            .blacklist_token(
                &decoded_refresh_token.signature,
                refresh_token_claims_clone.expiration,
            )
            .unwrap();

        let req = TestRequest::post()
            .uri("/api/auth/token/refresh")
            .insert_header(("RefreshToken", refresh_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();
        assert_eq!(resp_err.err_type, ErrorType::TokenExpired as i32);
    }

    #[actix_web::test]
    async fn test_refresh_tokens_with_invalid_token() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let req = TestRequest::post()
            .uri("/api/auth/token/refresh")
            .insert_header(("RefreshToken", "invalid_token"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();
        assert_eq!(resp_err.err_type, ErrorType::IncorrectCredential as i32);
    }

    #[actix_web::test]
    async fn test_logout_success() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, _, _) = test_utils::create_user().await;

        // Create a valid refresh token
        let refresh_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: (SystemTime::now() + env::CONF.refresh_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            token_type: AuthTokenType::Refresh,
        };

        let refresh_token =
            AuthToken::sign_new(refresh_token_claims.clone(), &env::CONF.token_signing_key);

        let req = TestRequest::post()
            .uri("/api/auth/logout")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("RefreshToken", refresh_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let auth_dao = db::auth::Dao::new(&env::testing::DB_THREAD_POOL);
        let decoded_refresh_token = AuthToken::decode(&refresh_token).unwrap();
        let is_blacklisted = auth_dao
            .check_is_token_on_blacklist_and_blacklist(
                &decoded_refresh_token.signature,
                refresh_token_claims.expiration,
            )
            .unwrap();
        assert!(is_blacklisted);

        let req = TestRequest::post()
            .uri("/api/auth/token/refresh")
            .insert_header(("RefreshToken", refresh_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();
        assert_eq!(resp_err.err_type, ErrorType::TokenExpired as i32);
    }

    #[actix_web::test]
    async fn test_logout_with_mismatched_user_ids() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token1, _, _) = test_utils::create_user().await;
        let (user2, _, _, _) = test_utils::create_user().await;

        // Create a refresh token for a different user
        let refresh_token_claims = NewAuthTokenClaims {
            user_id: user2.id,
            user_email: &user2.email,
            expiration: (SystemTime::now() + env::CONF.refresh_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            token_type: AuthTokenType::Refresh,
        };

        let refresh_token = AuthToken::sign_new(refresh_token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::post()
            .uri("/api/auth/logout")
            .insert_header(("AccessToken", access_token1.as_str()))
            .insert_header(("RefreshToken", refresh_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();
        assert_eq!(resp_err.err_type, ErrorType::UserDisallowed as i32);
    }

    #[actix_web::test]
    async fn test_logout_with_already_blacklisted_token() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, _, _) = test_utils::create_user().await;

        // Create a valid refresh token
        let refresh_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: (SystemTime::now() + env::CONF.refresh_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            token_type: AuthTokenType::Refresh,
        };

        let refresh_token =
            AuthToken::sign_new(refresh_token_claims.clone(), &env::CONF.token_signing_key);

        // Blacklist the token first
        let auth_dao = db::auth::Dao::new(&env::testing::DB_THREAD_POOL);
        let decoded_refresh_token = AuthToken::decode(&refresh_token).unwrap();
        auth_dao
            .blacklist_token(
                &decoded_refresh_token.signature,
                refresh_token_claims.expiration,
            )
            .unwrap();

        let req = TestRequest::post()
            .uri("/api/auth/logout")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("RefreshToken", refresh_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();
        assert_eq!(resp_err.err_type, ErrorType::ConflictWithExisting as i32);
    }

    #[actix_web::test]
    async fn test_logout_with_invalid_refresh_token() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let req = TestRequest::post()
            .uri("/api/auth/logout")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("RefreshToken", "invalid_token"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();
        assert_eq!(resp_err.err_type, ErrorType::IncorrectCredential as i32);
    }
}
