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
use zeroize::Zeroizing;

use crate::env;
use crate::handlers::{self, error::HttpErrorResponse};
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
    hasher.update(env::CONF.token_signing_key);
    let hash = hasher.finalize();

    let phony_salt = hash[..16].to_vec();
    // The bounds are hardcoded. This is safe.
    let phony_nonce =
        unsafe { i32::from_be_bytes(hash.get_unchecked(16..20).try_into().unwrap_unchecked()) };

    let phony_params = SigninNonceAndHashParams {
        auth_string_salt: phony_salt,
        auth_string_memory_cost_kib: 125000,
        auth_string_parallelism_factor: 2,
        auth_string_iters: 18,
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
    let credentials = Zeroizing::new(credentials.0);

    if let Validity::Invalid(msg) = validators::validate_email_address(&credentials.email) {
        return Err(HttpErrorResponse::IncorrectlyFormed(msg));
    }

    throttle
        .enforce(&credentials.email, "sign_in", &db_thread_pool)
        .await?;

    let credentials = Arc::new(credentials);
    let credentials_ref = Arc::clone(&credentials);

    let auth_dao = db::auth::Dao::new(&db_thread_pool);

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
    let auth_dao = db::auth::Dao::new(&db_thread_pool);

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
    signin_token: UnverifiedToken<SignIn, FromHeader>,
    code: ProtoBuf<BackupCode>,
    throttle: Throttle<5, 60>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let code = Zeroizing::new(code.0);

    let claims = signin_token.verify()?;
    let user_id = claims.user_id;

    throttle
        .enforce(&user_id, "use_backup_code_for_signin", &db_thread_pool)
        .await?;

    match web::block(move || {
        let auth_dao = db::auth::Dao::new(&db_thread_pool);
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
        let auth_dao = db::auth::Dao::new(&db_thread_pool);
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    use entries_utils::messages::{ErrorType, NewUser, ServerErrorResponse};
    use entries_utils::models::user_otp::UserOtp;
    use entries_utils::schema::{signin_nonces, user_otps, users};

    use actix_protobuf::ProtoBufConfig;
    use actix_web::body::to_bytes;
    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::web::Data;
    use actix_web::App;
    use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
    use entries_utils::token::Token;
    use prost::Message;

    use crate::handlers::test_utils::{self, gen_bytes};

    #[actix_web::test]
    async fn test_obtain_nonce_and_auth_string_params() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(crate::services::api::configure),
        )
        .await;

        let (user, _) = test_utils::create_user().await;

        let salt = gen_bytes(16);
        let nonce = i32::MAX;

        diesel::update(users::table.find(user.id))
            .set((
                users::auth_string_salt.eq(&salt),
                users::auth_string_memory_cost_kib.eq(10),
                users::auth_string_parallelism_factor.eq(10),
                users::auth_string_iters.eq(10),
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
        assert_eq!(resp_body.auth_string_salt, salt);
        assert_eq!(resp_body.auth_string_memory_cost_kib, 10);
        assert_eq!(resp_body.auth_string_parallelism_factor, 10);
        assert_eq!(resp_body.auth_string_iters, 10);

        // Fake user
        let req = TestRequest::get()
            .uri("/api/auth/nonce_and_auth_string_params?email=fake@fakerson.com")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = SigninNonceAndHashParams::decode(resp_body).unwrap();

        let first_salt = resp_body.auth_string_salt.clone();
        let first_nonce = resp_body.nonce;

        assert_eq!(resp_body.auth_string_memory_cost_kib, 125000);
        assert_eq!(resp_body.auth_string_parallelism_factor, 2);
        assert_eq!(resp_body.auth_string_iters, 18);

        // Should be the same nonce and salt, even for a fake user
        let req = TestRequest::get()
            .uri("/api/auth/nonce_and_auth_string_params?email=fake@fakerson.com")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = SigninNonceAndHashParams::decode(resp_body).unwrap();

        assert_eq!(resp_body.nonce, first_nonce);
        assert_eq!(resp_body.auth_string_salt, first_salt);
        assert_eq!(resp_body.auth_string_memory_cost_kib, 125000);
        assert_eq!(resp_body.auth_string_parallelism_factor, 2);
        assert_eq!(resp_body.auth_string_iters, 18);

        // Different fake email should have a different nonce and salt
        let req = TestRequest::get()
            .uri("/api/auth/nonce_and_auth_string_params?email=anotherfake@fake.com")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = SigninNonceAndHashParams::decode(resp_body).unwrap();

        assert_ne!(resp_body.nonce, first_nonce);
        assert_ne!(resp_body.auth_string_salt, first_salt);
        assert_eq!(resp_body.auth_string_memory_cost_kib, 125000);
        assert_eq!(resp_body.auth_string_parallelism_factor, 2);
        assert_eq!(resp_body.auth_string_iters, 18);
    }

    #[actix_web::test]
    async fn test_sign_in() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(crate::services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let auth_string = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(format!("password{user_number}").as_bytes())
            .unwrap();

        let new_user = NewUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: Vec::from(auth_string.as_bytes()),

            auth_string_salt: Vec::from(auth_string.salt_bytes()),
            auth_string_memory_cost_kib: 128,
            auth_string_parallelism_factor: 1,
            auth_string_iters: 2,

            password_encryption_salt: gen_bytes(10),
            password_encryption_memory_cost_kib: 1024,
            password_encryption_parallelism_factor: 1,
            password_encryption_iters: 1,

            recovery_key_salt: gen_bytes(10),
            recovery_key_memory_cost_kib: 1024,
            recovery_key_parallelism_factor: 1,
            recovery_key_iters: 1,

            encryption_key_encrypted_with_password: gen_bytes(10),
            encryption_key_encrypted_with_recovery_key: gen_bytes(10),

            public_key: gen_bytes(10),

            preferences_encrypted: gen_bytes(10),
            user_keystore_encrypted: gen_bytes(10),
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
        let token_type = AuthTokenType::try_from(signin_token.claims.typ).unwrap();

        assert!(matches!(token_type, AuthTokenType::SignIn));

        let claims = signin_token.claims;
        let decrypted_claims = claims.decrypt(&env::CONF.token_encryption_cipher).unwrap();

        assert_eq!(decrypted_claims.user_email, new_user.email);
        assert!(
            decrypted_claims.expiration
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
                .configure(crate::services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let auth_string = argon2_kdf::Hasher::new()
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(format!("password{user_number}").as_bytes())
            .unwrap();

        let new_user = NewUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: Vec::from(auth_string.as_bytes()),

            auth_string_salt: Vec::from(auth_string.salt_bytes()),
            auth_string_memory_cost_kib: 128,
            auth_string_parallelism_factor: 1,
            auth_string_iters: 2,

            password_encryption_salt: gen_bytes(10),
            password_encryption_memory_cost_kib: 1024,
            password_encryption_parallelism_factor: 1,
            password_encryption_iters: 1,

            recovery_key_salt: gen_bytes(10),
            recovery_key_memory_cost_kib: 1024,
            recovery_key_parallelism_factor: 1,
            recovery_key_iters: 1,

            encryption_key_encrypted_with_password: gen_bytes(10),
            encryption_key_encrypted_with_recovery_key: gen_bytes(10),

            public_key: gen_bytes(10),

            preferences_encrypted: gen_bytes(10),
            user_keystore_encrypted: gen_bytes(10),
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

        let mut bad_signin_token = signin_token.value.clone();
        bad_signin_token.pop().unwrap();
        bad_signin_token.pop().unwrap();
        bad_signin_token.pop().unwrap();
        bad_signin_token.pop().unwrap();

        let req = TestRequest::post()
            .uri("/api/auth/otp/verify")
            .insert_header(("Content-Type", "application/protobuf"))
            .insert_header(("SignInToken", bad_signin_token))
            .set_payload(otp_msg.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

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
            AuthTokenType::try_from(access_token.claims.typ).unwrap(),
            AuthTokenType::Access
        ));
        assert!(matches!(
            AuthTokenType::try_from(refresh_token.claims.typ).unwrap(),
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
                .configure(crate::services::api::configure),
        )
        .await;

        let (user, access_token) = test_utils::create_user().await;

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

        // See if the new OTP is contained in the response body (it shouldn't be)
        let mut match_count = 0;
        let mut found_match = false;
        for byte in resp_body {
            if byte == new_otp.otp.as_bytes()[match_count] {
                match_count += 1;
            } else {
                match_count = 0;
            }

            if match_count == new_otp.otp.len() {
                found_match = true;
                break;
            }
        }

        assert!(!found_match);
        assert!(old_otp.otp != new_otp.otp);
    }
}
