use entries_common::db::{self, DaoError, DbThreadPool};
use entries_common::email::EmailSender;
use entries_common::messages::{
    BackupCode, BackupCodeList, CredentialPair, EmailQuery, SigninNonceAndHashParams, SigninToken,
};
use entries_common::messages::{Otp as OtpMessage, TokenPair};
use entries_common::otp::Otp;
use entries_common::token::auth_token::{AuthToken, AuthTokenType, NewAuthTokenClaims};
use entries_common::validators::{self, Validity};

use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
use actix_web::{web, HttpResponse};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::env;
use crate::handlers::{self, error::DoesNotExistType, error::HttpErrorResponse};
use crate::middleware::auth::{Access, Refresh, SignIn, UnverifiedToken, VerifiedToken};
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
    let credentials = Zeroizing::new(credentials.0);

    if let Validity::Invalid(msg) = validators::validate_email_address(&credentials.email) {
        return Err(HttpErrorResponse::IncorrectlyFormed(String::from(msg)));
    }

    let credentials = Arc::new(credentials);
    let credentials_ref = Arc::clone(&credentials);

    let auth_dao = db::auth::Dao::new(&db_thread_pool);

    let nonce =
        match web::block(move || auth_dao.get_and_refresh_signin_nonce(&credentials_ref.email))
            .await?
        {
            Ok(a) => a,
            Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("User not found"),
                    DoesNotExistType::User,
                ));
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
            return Err(HttpErrorResponse::DoesNotExist(
                String::from("User not found"),
                DoesNotExistType::User,
            ));
        }
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to get user auth string hash",
            )));
        }
    };

    if !hash_and_status.is_user_verified {
        return Err(HttpErrorResponse::PendingAction(String::from(
            "User has not accepted verification email",
        )));
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

    Ok(HttpResponse::Ok().protobuf(token_pair)?)
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

pub async fn use_backup_code_for_signin(
    db_thread_pool: web::Data<DbThreadPool>,
    signin_token: UnverifiedToken<SignIn, FromHeader>,
    code: ProtoBuf<BackupCode>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let code = Zeroizing::new(code.0);

    let claims = signin_token.verify()?;
    let user_id = claims.user_id;

    match web::block(move || {
        let auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.delete_backup_code(&code.value, user_id)
    })
    .await?
    {
        Ok(_) => (),
        Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
            return Err(HttpErrorResponse::IncorrectCredential(String::from(
                "Backup codes was incorrect",
            )));
        }
        Err(e) => log::error!("{e}"),
    };

    let now = SystemTime::now();

    let refresh_token_claims = NewAuthTokenClaims {
        user_id: claims.user_id,
        user_email: &claims.user_email,
        expiration: (now + env::CONF.refresh_token_lifetime)
            .duration_since(UNIX_EPOCH)
            .expect("System time should be after Unix Epoch")
            .as_secs(),
        token_type: AuthTokenType::Refresh,
    };

    let refresh_token = AuthToken::sign_new(refresh_token_claims, &env::CONF.token_signing_key);

    let access_token_claims = NewAuthTokenClaims {
        user_id: claims.user_id,
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

    Ok(HttpResponse::Ok().protobuf(token_pair)?)
}

pub async fn regenerate_backup_codes(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    otp: ProtoBuf<OtpMessage>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let user_id = user_access_token.0.user_id;

    handlers::verification::verify_otp(
        &otp.value,
        &user_access_token.0.user_email,
        &db_thread_pool,
    )
    .await?;

    let backup_codes = Arc::new(Otp::generate_multiple(12, 8));
    let backup_codes_ref = Arc::clone(&backup_codes);

    match web::block(move || {
        let auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.replace_backup_codes(user_id, &backup_codes_ref)
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to replace backup codes",
            )));
        }
    };

    let backup_codes = Arc::into_inner(backup_codes)
        .expect("Multiple references exist to data that should only have one reference");

    let resp_body = BackupCodeList { backup_codes };

    Ok(HttpResponse::Ok().protobuf(resp_body)?)
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

    use entries_common::messages::{ErrorType, NewUser, ServerErrorResponse};
    use entries_common::models::user_otp::UserOtp;
    use entries_common::schema::{signin_nonces, user_otps, users};
    use entries_common::threadrand::SecureRng;

    use actix_protobuf::ProtoBufConfig;
    use actix_web::body::to_bytes;
    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::web::Data;
    use actix_web::App;
    use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
    use entries_common::token::Token;
    use prost::Message;
    use uuid::Uuid;

    use crate::handlers::test_utils::{self, gen_bytes};
    use crate::services::api::RouteLimiters;

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

            recovery_key_hash_salt: gen_bytes(10),
            recovery_key_hash_mem_cost_kib: 1024,
            recovery_key_hash_threads: 1,
            recovery_key_hash_iterations: 1,

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

            recovery_key_hash_salt: gen_bytes(10),
            recovery_key_hash_mem_cost_kib: 1024,
            recovery_key_hash_threads: 1,
            recovery_key_hash_iterations: 1,

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
        let resp_body = TokenPair::decode(resp_body).unwrap();

        let access_token = AuthToken::decode(&resp_body.access_token).unwrap();
        let refresh_token = AuthToken::decode(&resp_body.refresh_token).unwrap();

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
}
