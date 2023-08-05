use entries_utils::db::{self, DaoError, DbThreadPool};
use entries_utils::email::EmailSender;
use entries_utils::messages::{
    BackupCode, BackupCodeList, CredentialPair, EmailQuery, SigninNonceAndHashParams, SigninToken,
};
use entries_utils::messages::{Otp as OtpMessage, TokenPair};
use entries_utils::otp::Otp;
use entries_utils::token::auth_token::{AuthToken, AuthTokenType, NewAuthTokenClaims};
use entries_utils::validators::{self, Validity};

use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
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
    email: web::Query<EmailQuery>,
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

    let phony_params = SigninNonceAndHashParams {
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
            return Ok(HttpResponse::Ok().protobuf(phony_params)?);
        }
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(
                "Failed to obtain nonce or authentication string data",
            ));
        }
    };

    Ok(HttpResponse::Ok().protobuf(real_params)?)
}

pub async fn sign_in(
    db_thread_pool: web::Data<DbThreadPool>,
    smtp_thread_pool: web::Data<EmailSender>,
    credentials: ProtoBuf<CredentialPair>,
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

    let signin_token_claims = NewAuthTokenClaims {
        user_id,
        user_email: &credentials.email,
        expiration: SystemTime::now() + env::CONF.signin_token_lifetime,
        token_type: AuthTokenType::SignIn,
    };

    let signin_token = AuthToken::sign_new(
        signin_token_claims.encrypt(&env::CONF.token_encryption_cipher),
        &env::CONF.token_signing_key,
    );

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
    _app_version: AppVersion,
    signin_token: UnverifiedToken<SignIn, FromHeader>,
    otp: ProtoBuf<OtpMessage>,
    throttle: Throttle<8, 10>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let claims = signin_token.verify()?;
    let user_id = claims.user_id;

    throttle
        .enforce(&user_id, "verify_otp_for_signin", &db_thread_pool)
        .await?;

    handlers::verification::verify_otp(&otp.value, &claims.user_email, &db_thread_pool).await?;

    let now = SystemTime::now();

    let refresh_token_claims = NewAuthTokenClaims {
        user_id,
        user_email: &claims.user_email,
        expiration: now + env::CONF.refresh_token_lifetime,
        token_type: AuthTokenType::Refresh,
    };

    let refresh_token = AuthToken::sign_new(
        refresh_token_claims.encrypt(&env::CONF.token_encryption_cipher),
        &env::CONF.token_signing_key,
    );

    let access_token_claims = NewAuthTokenClaims {
        user_id,
        user_email: &claims.user_email,
        expiration: now + env::CONF.access_token_lifetime,
        token_type: AuthTokenType::Access,
    };

    let access_token = AuthToken::sign_new(
        access_token_claims.encrypt(&env::CONF.token_encryption_cipher),
        &env::CONF.token_signing_key,
    );

    let token_pair = TokenPair {
        access_token,
        refresh_token,
        server_time: SystemTime::now().try_into()?,
    };

    Ok(HttpResponse::Ok().protobuf(token_pair)?)
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
    code: ProtoBuf<BackupCode>,
    throttle: Throttle<5, 60>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let claims = signin_token.verify()?;
    let user_id = claims.user_id;

    throttle
        .enforce(&user_id, "use_backup_code_for_signin", &db_thread_pool)
        .await?;

    match web::block(move || {
        let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.delete_backup_code(&code.value, user_id)
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

    let refresh_token_claims = NewAuthTokenClaims {
        user_id: claims.user_id,
        user_email: &claims.user_email,
        expiration: now + env::CONF.refresh_token_lifetime,
        token_type: AuthTokenType::Refresh,
    };

    let refresh_token = AuthToken::sign_new(
        refresh_token_claims.encrypt(&env::CONF.token_encryption_cipher),
        &env::CONF.token_signing_key,
    );

    let access_token_claims = NewAuthTokenClaims {
        user_id: claims.user_id,
        user_email: &claims.user_email,
        expiration: now + env::CONF.access_token_lifetime,
        token_type: AuthTokenType::Access,
    };

    let access_token = AuthToken::sign_new(
        access_token_claims.encrypt(&env::CONF.token_encryption_cipher),
        &env::CONF.token_signing_key,
    );

    let token_pair = TokenPair {
        access_token,
        refresh_token,
        server_time: SystemTime::now().try_into()?,
    };

    Ok(HttpResponse::Ok().protobuf(token_pair)?)
}

pub async fn regenerate_backup_codes(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    otp: ProtoBuf<OtpMessage>,
    throttle: Throttle<6, 15>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let user_id = user_access_token.0.user_id;

    throttle
        .enforce(&user_id, "regenerate_backup_codes", &db_thread_pool)
        .await?;

    handlers::verification::verify_otp(
        &otp.value,
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

    let backup_codes = Arc::into_inner(backup_codes)
        .expect("Multiple references exist to data that should only have one reference");

    let resp_body = BackupCodeList { backup_codes };

    Ok(HttpResponse::Ok().protobuf(resp_body)?)
}

pub async fn refresh_tokens(
    db_thread_pool: web::Data<DbThreadPool>,
    _app_version: AppVersion,
    token: UnverifiedToken<Refresh, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let token_claims = token.verify()?;
    let token_expiration = token_claims.expiration;

    match web::block(move || {
        let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.check_is_token_on_blacklist_and_blacklist(&token.0.signature, token_expiration)
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

    let refresh_token_claims = NewAuthTokenClaims {
        user_id: token_claims.user_id,
        user_email: &token_claims.user_email,
        expiration: now + env::CONF.refresh_token_lifetime,
        token_type: AuthTokenType::Refresh,
    };

    let refresh_token = AuthToken::sign_new(
        refresh_token_claims.encrypt(&env::CONF.token_encryption_cipher),
        &env::CONF.token_signing_key,
    );

    let access_token_claims = NewAuthTokenClaims {
        user_id: token_claims.user_id,
        user_email: &token_claims.user_email,
        expiration: now + env::CONF.access_token_lifetime,
        token_type: AuthTokenType::Access,
    };

    let access_token = AuthToken::sign_new(
        access_token_claims.encrypt(&env::CONF.token_encryption_cipher),
        &env::CONF.token_signing_key,
    );

    let token_pair = TokenPair {
        access_token,
        refresh_token,
        server_time: SystemTime::now().try_into()?,
    };

    Ok(HttpResponse::Ok().protobuf(token_pair)?)
}

pub async fn logout(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    refresh_token: UnverifiedToken<Refresh, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let refresh_token_claims = refresh_token.verify()?;

    if refresh_token_claims.user_id != user_access_token.0.user_id {
        return Err(HttpErrorResponse::UserDisallowed(
            "Refresh token does not belong to user.",
        ));
    }

    match web::block(move || {
        let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.blacklist_token(&refresh_token.0.signature, refresh_token_claims.expiration)
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
