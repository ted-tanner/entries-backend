use entries_utils::db::{self, DaoError, DbThreadPool};
use entries_utils::email::EmailSender;
use entries_utils::otp::Otp;
use entries_utils::request_io::{
    CredentialPair, InputBackupCode, InputEmail, InputOtp, OutputBackupCodes,
    OutputSigninNonceAndHashParams, SigninToken, TokenPair,
};
use entries_utils::token::auth_token::{AuthToken, AuthTokenType};
use entries_utils::token::Token;
use entries_utils::validators::{self, Validity};

use actix_web::{web, HttpResponse};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::env;
use crate::handlers::{self, error::HttpErrorResponse};
use crate::middleware::app_version::AppVersion;
use crate::middleware::auth::{Access, Refresh, SignIn, UnverifiedToken, VerifiedToken};
use crate::middleware::throttle::Throttle;
use crate::middleware::FromHeader;

pub async fn obtain_nonce_and_auth_string_params(
    db_thread_pool: web::Data<DbThreadPool>,
    email: web::Query<InputEmail>,
) -> Result<HttpResponse, HttpErrorResponse> {
    // Disguise that the user doesn't exist by returning random data that only changes
    // once per day. Do this even for valid requests to prevent timing attacks
    let unix_day = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86400;
    let mut rng = ChaCha20Rng::seed_from_u64(unix_day);

    let random: u64 = rng.gen();

    let mut hasher = Sha256::new();
    hasher.update(&*email.email);
    hasher.update(random.to_be_bytes());
    let hash = hasher.finalize();

    let phony_salt = hash[..16].to_vec();
    // The bounds are hardcoded. This is safe.
    let phony_nonce = unsafe { i32::from_be_bytes(hash[16..20].try_into().unwrap_unchecked()) };

    let phony_params = OutputSigninNonceAndHashParams {
        auth_string_salt: phony_salt,
        auth_string_memory_cost_kib: 250000,
        auth_string_parallelism_factor: 2,
        auth_string_iters: 18,
        nonce: phony_nonce,
    };

    let real_params = match web::block(move || {
        let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.get_auth_string_data_signin_nonce(&email.0.email)
    })
    .await?
    {
        Ok(a) => a,
        Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
            return Ok(HttpResponse::Ok().json(phony_params));
        }
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(
                "Failed to obtain nonce or authentication string data",
            ));
        }
    };

    Ok(HttpResponse::Ok().json(real_params))
}

pub async fn sign_in(
    db_thread_pool: web::Data<DbThreadPool>,
    smtp_thread_pool: web::Data<EmailSender>,
    credentials: web::Json<CredentialPair>,
    throttle: Throttle<8, 10>,
) -> Result<HttpResponse, HttpErrorResponse> {
    if let Validity::Invalid(msg) = validators::validate_email_address(&credentials.email) {
        return Err(HttpErrorResponse::IncorrectlyFormed(msg));
    }

    throttle
        .enforce(&credentials.email, "sign_in", &db_thread_pool)
        .await?;

    let credentials = Arc::new(credentials);
    let credentials_ref = Arc::clone(&credentials);

    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);

    let nonce =
        match web::block(move || auth_dao.get_and_refresh_signin_nonce(&credentials_ref.email))
            .await?
        {
            Ok(a) => a,
            Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
                return Err(HttpErrorResponse::DoesNotExist("User not found"));
            }
            Err(e) => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(
                    "Failed to obtain sign-in nonce",
                ));
            }
        };

    if nonce != credentials.nonce {
        return Err(HttpErrorResponse::IncorrectNonce("Incorrect nonce"));
    }

    let credentials_ref = Arc::clone(&credentials);
    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);

    let hash_and_status = match web::block(move || {
        auth_dao.get_user_auth_string_hash_and_status(&credentials_ref.email)
    })
    .await?
    {
        Ok(a) => a,
        Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
            return Err(HttpErrorResponse::DoesNotExist("User not found"));
        }
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(
                "Failed to get user auth string hash",
            ));
        }
    };

    if !hash_and_status.is_user_verified {
        return Err(HttpErrorResponse::PendingAction(
            "User has not accepted verification email",
        ));
    }

    let user_id = hash_and_status.user_id;

    handlers::verification::verify_auth_string(
        &credentials.auth_string,
        &credentials.email,
        &db_thread_pool,
    )
    .await?;

    let mut signin_token = AuthToken::new(
        user_id,
        &credentials.email,
        SystemTime::now() + env::CONF.lifetimes.signin_token_lifetime,
        AuthTokenType::SignIn,
    );

    signin_token.encrypt(&env::CONF.keys.token_encryption_cipher);

    let signin_token = SigninToken {
        signin_token: signin_token.sign_and_encode(&env::CONF.keys.token_signing_key),
    };

    handlers::verification::generate_and_email_otp(
        &credentials.email,
        db_thread_pool.as_ref(),
        smtp_thread_pool.as_ref(),
    )
    .await?;

    Ok(HttpResponse::Ok().json(signin_token))
}

pub async fn verify_otp_for_signin(
    db_thread_pool: web::Data<DbThreadPool>,
    _app_version: AppVersion,
    signin_token: UnverifiedToken<SignIn, FromHeader>,
    otp: web::Json<InputOtp>,
    throttle: Throttle<8, 10>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let claims = signin_token.verify()?;
    let user_id = claims.user_id;

    throttle
        .enforce(&user_id, "verify_otp_for_signin", &db_thread_pool)
        .await?;

    handlers::verification::verify_otp(&otp.otp, &claims.user_email, &db_thread_pool)
        .await?;

    let now = SystemTime::now();

    let mut refresh_token = AuthToken::new(
        claims.user_id,
        &claims.user_email,
        now + env::CONF.lifetimes.refresh_token_lifetime,
        AuthTokenType::Refresh,
    );

    let mut access_token = AuthToken::new(
        claims.user_id,
        &claims.user_email,
        now + env::CONF.lifetimes.access_token_lifetime,
        AuthTokenType::Access,
    );

    refresh_token.encrypt(&env::CONF.keys.token_encryption_cipher);
    access_token.encrypt(&env::CONF.keys.token_encryption_cipher);

    let token_pair = TokenPair {
        access_token: access_token.sign_and_encode(&env::CONF.keys.token_signing_key),
        refresh_token: refresh_token.sign_and_encode(&env::CONF.keys.token_signing_key),
        server_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_millis(),
    };

    Ok(HttpResponse::Ok().json(token_pair))
}

pub async fn obtain_otp(
    db_thread_pool: web::Data<DbThreadPool>,
    smtp_thread_pool: web::Data<EmailSender>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    throttle: Throttle<4, 10>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let user_id = user_access_token.0.user_id;

    throttle
        .enforce(&user_id, "sign_in", &db_thread_pool)
        .await?;

    handlers::verification::generate_and_email_otp(
        &user_access_token.0.user_email,
        db_thread_pool.as_ref(),
        smtp_thread_pool.as_ref(),
    )
    .await?;

    Ok(HttpResponse::Ok().finish())
}

pub async fn use_backup_code_for_signin(
    db_thread_pool: web::Data<DbThreadPool>,
    _app_version: AppVersion,
    signin_token: UnverifiedToken<SignIn, FromHeader>,
    code: web::Json<InputBackupCode>,
    throttle: Throttle<5, 60>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let claims = signin_token.verify()?;
    let user_id = claims.user_id;

    throttle
        .enforce(&user_id, "use_backup_code_for_signin", &db_thread_pool)
        .await?;

    match web::block(move || {
        let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.delete_backup_code(&code.code, user_id)
    })
    .await?
    {
        Ok(_) => (),
        Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
            return Err(HttpErrorResponse::IncorrectCredential(
                "Backup codes was incorrect",
            ));
        }
        Err(e) => log::error!("{e}"),
    };

    let now = SystemTime::now();

    let mut refresh_token = AuthToken::new(
        claims.user_id,
        &claims.user_email,
        now + env::CONF.lifetimes.refresh_token_lifetime,
        AuthTokenType::Refresh,
    );

    let mut access_token = AuthToken::new(
        claims.user_id,
        &claims.user_email,
        now + env::CONF.lifetimes.access_token_lifetime,
        AuthTokenType::Access,
    );

    refresh_token.encrypt(&env::CONF.keys.token_encryption_cipher);
    access_token.encrypt(&env::CONF.keys.token_encryption_cipher);

    let token_pair = TokenPair {
        access_token: access_token.sign_and_encode(&env::CONF.keys.token_signing_key),
        refresh_token: refresh_token.sign_and_encode(&env::CONF.keys.token_signing_key),
        server_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_millis(),
    };

    Ok(HttpResponse::Ok().json(token_pair))
}

pub async fn regenerate_backup_codes(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    otp: web::Json<InputOtp>,
    throttle: Throttle<6, 15>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let user_id = user_access_token.0.user_id;

    throttle
        .enforce(&user_id, "regenerate_backup_codes", &db_thread_pool)
        .await?;

    handlers::verification::verify_otp(
        &otp.otp,
        &user_access_token.0.user_email,
        &db_thread_pool,
    )
    .await?;

    let backup_codes = Arc::new(Otp::generate_multiple(12, 8));
    let backup_codes_ref = Arc::clone(&backup_codes);

    match web::block(move || {
        let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.replace_backup_codes(user_id, &backup_codes_ref)
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(
                "Failed to replace backup codes",
            ));
        }
    };

    Ok(HttpResponse::Ok().json(OutputBackupCodes {
        backup_codes: &backup_codes,
    }))
}

pub async fn refresh_tokens(
    db_thread_pool: web::Data<DbThreadPool>,
    _app_version: AppVersion,
    token: UnverifiedToken<Refresh, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let token_signature = match token.0.parts() {
        Some(p) => p.signature.clone(),
        None => return Err(HttpErrorResponse::IncorrectCredential("Invalid token")),
    };

    let token_claims = token.verify()?;

    let user_id = token_claims.user_id;
    let token_expiration = token_claims.expiration;

    match web::block(move || {
        let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.check_is_token_on_blacklist_and_blacklist(&token_signature, token_expiration)
    })
    .await?
    {
        Ok(false) => (),
        Ok(true) => {
            return Err(HttpErrorResponse::TokenExpired("Token has expired"));
        }
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError("Error verifying token"));
        }
    };

    let now = SystemTime::now();

    let mut refresh_token = AuthToken::new(
        user_id,
        &token_claims.user_email,
        now + env::CONF.lifetimes.refresh_token_lifetime,
        AuthTokenType::Refresh,
    );

    refresh_token.encrypt(&env::CONF.keys.token_encryption_cipher);

    let mut access_token = AuthToken::new(
        user_id,
        &token_claims.user_email,
        now + env::CONF.lifetimes.access_token_lifetime,
        AuthTokenType::Access,
    );

    access_token.encrypt(&env::CONF.keys.token_encryption_cipher);

    let token_pair = TokenPair {
        access_token: access_token.sign_and_encode(&env::CONF.keys.token_signing_key),
        refresh_token: refresh_token.sign_and_encode(&env::CONF.keys.token_signing_key),
        server_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_millis(),
    };

    Ok(HttpResponse::Ok().json(token_pair))
}

pub async fn logout(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    refresh_token: UnverifiedToken<Refresh, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let refresh_token_signature = match refresh_token.0.parts() {
        Some(p) => p.signature.clone(),
        None => return Err(HttpErrorResponse::IncorrectCredential("Invalid token")),
    };

    let refresh_token_claims = refresh_token.verify()?;

    if refresh_token_claims.user_id != user_access_token.0.user_id {
        return Err(HttpErrorResponse::UserDisallowed(
            "Refresh token does not belong to user.",
        ));
    }

    match web::block(move || {
        let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.blacklist_token(&refresh_token_signature, refresh_token_claims.expiration)
    })
    .await?
    {
        Ok(_) => (),
        Err(DaoError::QueryFailure(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ))) => {
            return Err(HttpErrorResponse::ConflictWithExisting(
                "Token already on blacklist",
            ));
        }
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(
                "Failed to blacklist token",
            ));
        }
    }

    Ok(HttpResponse::Ok().finish())
}
