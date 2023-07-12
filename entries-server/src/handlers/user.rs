use entries_utils::db::{self, DaoError, DbThreadPool};
use entries_utils::email::templates::UserVerificationMessage;
use entries_utils::email::{EmailMessage, EmailSender};
use entries_utils::html::templates::{
    DeleteUserAccountNotFoundPage, DeleteUserAlreadyScheduledPage, DeleteUserExpiredLinkPage,
    DeleteUserInternalErrorPage, DeleteUserInvalidLinkPage, DeleteUserLinkMissingTokenPage,
    DeleteUserSuccessPage, VerifyUserExpiredLinkPage, VerifyUserInternalErrorPage,
    VerifyUserInvalidLinkPage, VerifyUserLinkMissingTokenPage, VerifyUserSuccessPage,
};
use entries_utils::otp::Otp;
use entries_utils::request_io::{
    InputBudgetAccessTokenList, InputEditUserKeystore, InputEditUserPrefs, InputEmail,
    InputNewAuthStringAndEncryptedPassword, InputNewRecoveryKey, InputUser,
    OutputBackupCodesAndVerificationEmailSent, OutputIsUserListedForDeletion, OutputPublicKey,
    OutputVerificationEmailSent,
};
use entries_utils::token::auth_token::{AuthToken, AuthTokenType, NewAuthTokenClaims};
use entries_utils::token::budget_access_token::BudgetAccessToken;
use entries_utils::token::{Token, TokenError};
use entries_utils::validators::{self, Validity};

use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::oneshot;

use crate::env;
use crate::handlers::{self, error::HttpErrorResponse};
use crate::middleware::app_version::AppVersion;
use crate::middleware::auth::{Access, UnverifiedToken, UserCreation, UserDeletion, VerifiedToken};
use crate::middleware::throttle::Throttle;
use crate::middleware::{FromHeader, FromQuery};

pub async fn lookup_user_public_key(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    user_email: web::Query<InputEmail>,
    throttle: Throttle<15, 5>,
) -> Result<HttpResponse, HttpErrorResponse> {
    throttle
        .enforce(
            &user_access_token.0.user_id,
            "lookup_user_public_key",
            &db_thread_pool,
        )
        .await?;

    let public_key = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.get_user_public_key(&user_email.email)
    })
    .await?
    {
        Ok(k) => k,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    "No user with given email address",
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(
                    "Failed to get user's public key",
                ));
            }
        },
    };

    Ok(HttpResponse::Ok().json(OutputPublicKey { public_key }))
}

pub async fn create(
    db_thread_pool: web::Data<DbThreadPool>,
    smtp_thread_pool: web::Data<EmailSender>,
    _app_version: AppVersion,
    user_data: web::Json<InputUser>,
    throttle: Throttle<5, 60>,
) -> Result<HttpResponse, HttpErrorResponse> {
    if let Validity::Invalid(msg) = validators::validate_email_address(&user_data.email) {
        return Err(HttpErrorResponse::IncorrectlyFormed(msg));
    }

    if user_data.auth_string.len() > 512 {
        return Err(HttpErrorResponse::InputTooLong(
            "Provided password is too long. Max: 512 bytes",
        ));
    }

    throttle
        .enforce(&user_data.email, "create_user", &db_thread_pool)
        .await?;

    let user_data = Arc::new(user_data);
    let user_data_ref = Arc::clone(&user_data);

    let (sender, receiver) = oneshot::channel();

    rayon::spawn(move || {
        let hash_result = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.hashing.salt_length)
            .hash_length(env::CONF.hashing.hash_length)
            .iterations(env::CONF.hashing.hash_iterations)
            .memory_cost_kib(env::CONF.hashing.hash_mem_cost_kib)
            .threads(env::CONF.hashing.hash_threads)
            .secret(argon2_kdf::Secret::using_bytes(&env::CONF.keys.hashing_key))
            .hash(&user_data_ref.auth_string);

        let hash = match hash_result {
            Ok(h) => h,
            Err(e) => {
                sender.send(Err(e)).expect("Sending to channel failed");
                return;
            }
        };

        sender.send(Ok(hash)).expect("Sending to channel failed");
    });

    let auth_string_hash = match receiver.await? {
        Ok(s) => s,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(
                "Failed to hash auth atring",
            ));
        }
    };

    let backup_codes = Arc::new(Otp::generate_multiple(12, 8));
    let backup_codes_ref = Arc::clone(&backup_codes);

    let user_data_ref = Arc::clone(&user_data);

    let user_id = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.create_user(
            &user_data_ref.0,
            &auth_string_hash.to_string(),
            &backup_codes_ref,
        )
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            )) => {
                return Err(HttpErrorResponse::ConflictWithExisting(
                    "A user with the given email address already exists",
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError("Failed to create user"));
            }
        },
    };

    let user_creation_token_claims = NewAuthTokenClaims {
        user_id,
        user_email: &user_data.email,
        expiration: SystemTime::now() + env::CONF.lifetimes.user_creation_token_lifetime,
        token_type: AuthTokenType::UserCreation,
    };

    let user_creation_token = AuthToken::sign_new(
        user_creation_token_claims.encrypt(&env::CONF.keys.token_encryption_cipher),
        &env::CONF.keys.token_signing_key,
    );

    let message = EmailMessage {
        body: UserVerificationMessage::generate(
            &env::CONF.endpoints.user_verification_url,
            &user_creation_token,
            env::CONF.lifetimes.user_creation_token_lifetime,
        ),
        subject: "Verify your account",
        from: env::CONF.email.from_address.clone(),
        reply_to: env::CONF.email.reply_to_address.clone(),
        destination: &user_data.email,
        is_html: true,
    };

    match smtp_thread_pool.send(message).await {
        Ok(_) => (),
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(
                "Failed to send user verification token to user's email address",
            ));
        }
    };

    Ok(
        HttpResponse::Created().json(OutputBackupCodesAndVerificationEmailSent {
            email_sent: true,
            email_token_lifetime_hours: env::CONF.lifetimes.user_creation_token_lifetime.as_secs()
                / 3600,
            backup_codes: &backup_codes,
        }),
    )
}

pub async fn verify_creation(
    db_thread_pool: web::Data<DbThreadPool>,
    user_creation_token: UnverifiedToken<UserCreation, FromQuery>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let claims = match user_creation_token.verify() {
        Ok(c) => c,
        Err(TokenError::TokenExpired) => {
            return Ok(HttpResponse::Unauthorized()
                .content_type("text/html")
                .body(VerifyUserExpiredLinkPage::generate()));
        }
        Err(TokenError::TokenMissing) => {
            return Ok(HttpResponse::BadRequest()
                .content_type("text/html")
                .body(VerifyUserLinkMissingTokenPage::generate()));
        }
        Err(TokenError::WrongTokenType) | Err(TokenError::TokenInvalid) => {
            return Ok(HttpResponse::Unauthorized()
                .content_type("text/html")
                .body(VerifyUserInvalidLinkPage::generate()));
        }
    };

    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.verify_user_creation(claims.user_id)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => {
            log::error!("{e}");
            return Ok(HttpResponse::InternalServerError()
                .content_type("text/html")
                .body(VerifyUserInternalErrorPage::generate()));
        }
    };

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(VerifyUserSuccessPage::generate(&claims.user_email)))
}

pub async fn edit_preferences(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    new_prefs: web::Json<InputEditUserPrefs>,
) -> Result<HttpResponse, HttpErrorResponse> {
    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.update_user_prefs(
            user_access_token.0.user_id,
            &new_prefs.encrypted_blob,
            &new_prefs.expected_previous_data_hash,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::OutOfDateHash => {
                return Err(HttpErrorResponse::OutOfDate("Out of date hash"));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(
                    "Failed to update user preferences",
                ));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn edit_keystore(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    new_keystore: web::Json<InputEditUserKeystore>,
) -> Result<HttpResponse, HttpErrorResponse> {
    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.update_user_keystore(
            user_access_token.0.user_id,
            &new_keystore.encrypted_blob,
            &new_keystore.expected_previous_data_hash,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::OutOfDateHash => {
                return Err(HttpErrorResponse::OutOfDate("Out of date hash"));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(
                    "Failed to update user keystore",
                ));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn change_password(
    db_thread_pool: web::Data<DbThreadPool>,
    new_password_data: web::Json<InputNewAuthStringAndEncryptedPassword>,
    throttle: Throttle<6, 15>,
) -> Result<HttpResponse, HttpErrorResponse> {
    throttle
        .enforce(
            &new_password_data.user_email,
            "change_password",
            &db_thread_pool,
        )
        .await?;

    if new_password_data.new_auth_string.len() > 512 {
        return Err(HttpErrorResponse::InputTooLong(
            "Provided password is too long. Max: 512 bytes",
        ));
    }

    handlers::verification::verify_otp(
        &new_password_data.otp,
        &new_password_data.user_email,
        &db_thread_pool,
    )
    .await?;

    let new_password_data = Arc::new(new_password_data.0);
    let new_password_data_ref = Arc::clone(&new_password_data);

    let (sender, receiver) = oneshot::channel();

    rayon::spawn(move || {
        let hash_result = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.hashing.salt_length)
            .hash_length(env::CONF.hashing.hash_length)
            .iterations(env::CONF.hashing.hash_iterations)
            .memory_cost_kib(env::CONF.hashing.hash_mem_cost_kib)
            .threads(env::CONF.hashing.hash_threads)
            .secret(argon2_kdf::Secret::using_bytes(&env::CONF.keys.hashing_key))
            .hash(&new_password_data_ref.new_auth_string);

        let hash = match hash_result {
            Ok(h) => h,
            Err(e) => {
                sender.send(Err(e)).expect("Sending to channel failed");
                return;
            }
        };

        sender.send(Ok(hash)).expect("Sending to channel failed");
    });

    let auth_string_hash = match receiver.await? {
        Ok(s) => s,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(
                "Failed to hash auth atring",
            ));
        }
    };

    web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.update_password(
            &new_password_data.user_email,
            &auth_string_hash.to_string(),
            &new_password_data.auth_string_salt,
            new_password_data.auth_string_memory_cost_kib,
            new_password_data.auth_string_parallelism_factor,
            new_password_data.auth_string_iters,
            &new_password_data.password_encryption_salt,
            new_password_data.password_encryption_memory_cost_kib,
            new_password_data.password_encryption_parallelism_factor,
            new_password_data.password_encryption_iters,
            &new_password_data.encrypted_encryption_key,
        )
    })
    .await
    .map(|_| HttpResponse::Ok().finish())
    .map_err(|e| {
        log::error!("{e}");
        HttpErrorResponse::InternalError("Failed to update password")
    })
}

pub async fn change_recovery_key(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    new_recovery_key_data: web::Json<InputNewRecoveryKey>,
    throttle: Throttle<6, 15>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let user_id = user_access_token.0.user_id;

    throttle
        .enforce(&user_id, "change_recovery_key", &db_thread_pool)
        .await?;

    handlers::verification::verify_otp(
        &new_recovery_key_data.otp,
        &user_access_token.0.user_email,
        &db_thread_pool,
    )
    .await?;

    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.update_recovery_key(
            user_id,
            &new_recovery_key_data.recovery_key_salt,
            new_recovery_key_data.recovery_key_memory_cost_kib,
            new_recovery_key_data.recovery_key_parallelism_factor,
            new_recovery_key_data.recovery_key_iters,
            &new_recovery_key_data.encrypted_encryption_key,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(
                "Failed to update recovery key data",
            ));
        }
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn init_delete(
    db_thread_pool: web::Data<DbThreadPool>,
    smtp_thread_pool: web::Data<EmailSender>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_tokens: web::Json<InputBudgetAccessTokenList>,
) -> Result<HttpResponse, HttpErrorResponse> {
    const INVALID_ID_MSG: &str =
        "One of the provided budget access tokens is invalid or has an incorrect ID";

    let mut tokens = HashMap::new();
    let mut key_ids = Vec::new();
    let mut budget_ids = Vec::new();

    for token in budget_access_tokens.budget_access_tokens.iter() {
        let token = BudgetAccessToken::decode(token)
            .map_err(|_| HttpErrorResponse::IncorrectlyFormed(INVALID_ID_MSG))?;

        key_ids.push(token.claims.key_id);
        budget_ids.push(token.claims.budget_id);
        tokens.insert(token.claims.key_id, token);
    }

    let key_ids = Arc::new(key_ids);
    let key_ids_ref = Arc::clone(&key_ids);

    let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
    let public_keys = match web::block(move || {
        budget_dao.get_multiple_public_budget_keys(&key_ids_ref, &budget_ids)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(INVALID_ID_MSG));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(
                    "Failed to get budget data corresponding to budget access token",
                ));
            }
        },
    };

    if public_keys.len() != tokens.len() {
        return Err(HttpErrorResponse::DoesNotExist(INVALID_ID_MSG));
    }

    for key in public_keys {
        let token = match tokens.get(&key.key_id) {
            Some(t) => t,
            None => return Err(HttpErrorResponse::DoesNotExist(INVALID_ID_MSG)),
        };

        token.verify(&key.public_key)?;
    }

    let deletion_token_expiration =
        SystemTime::now() + env::CONF.lifetimes.user_deletion_token_lifetime;
    let delete_me_time = deletion_token_expiration
        + Duration::from_secs(env::CONF.time_delays.user_deletion_delay_days * 24 * 3600);

    let user_id = user_access_token.0.user_id;

    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.save_user_deletion_budget_keys(&key_ids, user_id, delete_me_time)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(INVALID_ID_MSG));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(
                    "Failed to save user deletion budget keys",
                ));
            }
        },
    }

    let user_deletion_token_claims = NewAuthTokenClaims {
        user_id: user_access_token.0.user_id,
        user_email: &user_access_token.0.user_email,
        expiration: SystemTime::now() + env::CONF.lifetimes.user_deletion_token_lifetime,
        token_type: AuthTokenType::UserDeletion,
    };

    let user_deletion_token = AuthToken::sign_new(
        user_deletion_token_claims.encrypt(&env::CONF.keys.token_encryption_cipher),
        &env::CONF.keys.token_signing_key,
    );

    let message = EmailMessage {
        body: UserVerificationMessage::generate(
            &env::CONF.endpoints.user_deletion_url,
            &user_deletion_token,
            env::CONF.lifetimes.user_deletion_token_lifetime,
        ),
        subject: "Confirm the deletion of your Entries App account",
        from: env::CONF.email.from_address.clone(),
        reply_to: env::CONF.email.reply_to_address.clone(),
        destination: &user_access_token.0.user_email,
        is_html: true,
    };

    match smtp_thread_pool.send(message).await {
        Ok(_) => (),
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(
                "Failed to send user deletion token to user's email address",
            ));
        }
    };

    Ok(HttpResponse::Ok().json(OutputVerificationEmailSent {
        email_sent: true,
        email_token_lifetime_hours: env::CONF.lifetimes.user_deletion_token_lifetime.as_secs()
            / 3600,
    }))
}

pub async fn delete(
    db_thread_pool: web::Data<DbThreadPool>,
    user_deletion_token: UnverifiedToken<UserDeletion, FromQuery>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let claims = match user_deletion_token.verify() {
        Ok(c) => c,
        Err(TokenError::TokenExpired) => {
            return Ok(HttpResponse::BadRequest()
                .content_type("text/html")
                .body(DeleteUserExpiredLinkPage::generate()));
        }
        Err(TokenError::TokenMissing) => {
            return Ok(HttpResponse::BadRequest()
                .content_type("text/html")
                .body(DeleteUserLinkMissingTokenPage::generate()));
        }
        Err(TokenError::WrongTokenType) | Err(TokenError::TokenInvalid) => {
            return Ok(HttpResponse::BadRequest()
                .content_type("text/html")
                .body(DeleteUserInvalidLinkPage::generate()));
        }
    };

    let user_id = claims.user_id;
    let days_until_deletion = env::CONF.time_delays.user_deletion_delay_days;

    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.initiate_user_deletion(
            user_id,
            Duration::from_secs(days_until_deletion * 24 * 60 * 60),
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            )) => {
                return Ok(HttpResponse::BadRequest()
                    .content_type("text/html")
                    .body(DeleteUserAlreadyScheduledPage::generate()));
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                log::error!(
                    "Failed to schedule user deletion after validating UserDeletionToken: {}",
                    e
                );
                return Ok(HttpResponse::BadRequest()
                    .content_type("text/html")
                    .body(DeleteUserAccountNotFoundPage::generate()));
            }
            _ => {
                log::error!("{e}");
                return Ok(HttpResponse::InternalServerError()
                    .content_type("text/html")
                    .body(DeleteUserInternalErrorPage::generate()));
            }
        },
    };

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(DeleteUserSuccessPage::generate(
            &claims.user_email,
            days_until_deletion,
        )))
}

pub async fn is_listed_for_deletion(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let is_listed_for_deletion = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.check_is_user_listed_for_deletion(user_access_token.0.user_id)
    })
    .await?
    {
        Ok(l) => l,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(
                "Failed to cancel user deletion",
            ));
        }
    };

    Ok(HttpResponse::Ok().json(OutputIsUserListedForDeletion {
        is_listed_for_deletion,
    }))
}

pub async fn cancel_delete(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.cancel_user_deletion(user_access_token.0.user_id)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(
                "Failed to cancel user deletion",
            ));
        }
    };

    Ok(HttpResponse::Ok().finish())
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use entries_utils::models::user::User;
    use entries_utils::models::user_deletion_request::UserDeletionRequest;
    use entries_utils::request_io::InputUser;
    use entries_utils::schema::signin_nonces::dsl::signin_nonces;
    use entries_utils::schema::user_backup_codes as user_backup_code_fields;
    use entries_utils::schema::user_backup_codes::dsl::user_backup_codes;
    use entries_utils::schema::user_deletion_request_budget_keys as user_deletion_request_budget_key_fields;
    use entries_utils::schema::user_deletion_request_budget_keys::dsl::user_deletion_request_budget_keys;
    use entries_utils::schema::user_deletion_requests as user_deletion_request_fields;
    use entries_utils::schema::user_deletion_requests::dsl::user_deletion_requests;
    use entries_utils::schema::user_keystores as user_keystore_fields;
    use entries_utils::schema::user_keystores::dsl::user_keystores;
    use entries_utils::schema::user_otps as user_otp_fields;
    use entries_utils::schema::user_otps::dsl::user_otps;
    use entries_utils::schema::user_preferences as user_preferences_fields;
    use entries_utils::schema::user_preferences::dsl::user_preferences;
    use entries_utils::schema::users as user_fields;
    use entries_utils::schema::users::dsl::users;

    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::web::Data;
    use actix_web::App;
    use base64::engine::general_purpose::STANDARD_NO_PAD as b64_nopad;
    use base64::Engine;
    use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
    use rand::Rng;
    use sha1::{Digest, Sha1};
    use std::str::FromStr;

    use crate::handlers::test_utils::{self, gen_bytes};
    use crate::middleware::auth::RequestAuthTokenType;

    #[actix_web::test]
    async fn test_lookup_user_public_key() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::from(env::testing::SMTP_THREAD_POOL.clone()))
                .configure(crate::services::api::configure),
        )
        .await;

        let (user, access_token) = test_utils::create_user().await;

        let req = TestRequest::get()
            .uri(&format!(
                "/api/user/lookup_user_public_key?email={}",
                user.email
            ))
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("AppVersion", "0.1.0"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_public_key = test::read_body_json::<OutputPublicKey, _>(resp).await;
        assert_eq!(user.public_key, resp_public_key.public_key);
    }

    #[actix_web::test]
    async fn test_create_user() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::from(env::testing::SMTP_THREAD_POOL.clone()))
                .configure(crate::services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: gen_bytes(10),

            auth_string_salt: gen_bytes(10),
            auth_string_memory_cost_kib: 1024,
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
            .uri("/api/user/create")
            .insert_header(("AppVersion", "0.1.0"))
            .set_json(&new_user)
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = test::try_read_body(resp).await.unwrap();
        let resp_body = String::from_utf8_lossy(&resp_body);

        let user = users
            .filter(user_fields::email.eq(&new_user.email))
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(user.email, new_user.email);
        assert_eq!(user.auth_string_salt, new_user.auth_string_salt);
        assert_eq!(
            user.auth_string_memory_cost_kib,
            new_user.auth_string_memory_cost_kib
        );
        assert_eq!(
            user.auth_string_parallelism_factor,
            new_user.auth_string_parallelism_factor
        );
        assert_eq!(user.auth_string_iters, new_user.auth_string_iters);
        assert_eq!(
            user.password_encryption_salt,
            new_user.password_encryption_salt
        );
        assert_eq!(
            user.password_encryption_memory_cost_kib,
            new_user.password_encryption_memory_cost_kib
        );
        assert_eq!(
            user.password_encryption_parallelism_factor,
            new_user.password_encryption_parallelism_factor
        );
        assert_eq!(
            user.password_encryption_iters,
            new_user.password_encryption_iters
        );
        assert_eq!(user.recovery_key_salt, new_user.recovery_key_salt);
        assert_eq!(
            user.recovery_key_memory_cost_kib,
            new_user.recovery_key_memory_cost_kib
        );
        assert_eq!(
            user.recovery_key_parallelism_factor,
            new_user.recovery_key_parallelism_factor
        );
        assert_eq!(user.recovery_key_iters, new_user.recovery_key_iters);
        assert_eq!(
            user.encryption_key_encrypted_with_password,
            new_user.encryption_key_encrypted_with_password
        );
        assert_eq!(
            user.encryption_key_encrypted_with_recovery_key,
            new_user.encryption_key_encrypted_with_recovery_key
        );
        assert_eq!(user.public_key, new_user.public_key);

        assert!(argon2_kdf::Hash::from_str(&user.auth_string_hash)
            .unwrap()
            .verify_with_secret(
                &new_user.auth_string,
                argon2_kdf::Secret::using_bytes(&env::CONF.keys.hashing_key),
            ));

        // Test password was hashed with correct params
        let hash_start_pos = user.auth_string_hash.rfind('$').unwrap() + 1;
        let hash_len: u32 = b64_nopad
            .decode(&user.auth_string_hash[hash_start_pos..])
            .unwrap()
            .len()
            .try_into()
            .unwrap();

        assert_eq!(hash_len, env::CONF.hashing.hash_length);

        let salt_start_pos = (&user.auth_string_hash[..(hash_start_pos - 1)])
            .rfind('$')
            .unwrap()
            + 1;
        let salt_end_pos = hash_start_pos - 1;
        let salt_len: u32 = b64_nopad
            .decode(&user.auth_string_hash[salt_start_pos..salt_end_pos])
            .unwrap()
            .len()
            .try_into()
            .unwrap();

        assert_eq!(salt_len, env::CONF.hashing.salt_length);

        assert!(user.auth_string_hash.contains("argon2id"));
        assert!(user
            .auth_string_hash
            .contains(&format!("m={}", env::CONF.hashing.hash_mem_cost_kib)));
        assert!(user
            .auth_string_hash
            .contains(&format!("t={}", env::CONF.hashing.hash_iterations)));
        assert!(user
            .auth_string_hash
            .contains(&format!("p={}", env::CONF.hashing.hash_threads)));

        // Get backup codes from response
        let codes_array_start = resp_body.find('[').unwrap() + 1;
        let codes_array_end = resp_body.find(']').unwrap();
        let backup_codes_array = resp_body[codes_array_start..codes_array_end].replace('"', "");
        let codes = backup_codes_array.split(',');

        let codes_from_db = user_backup_codes
            .select(user_backup_code_fields::code)
            .filter(user_backup_code_fields::user_id.eq(user.id))
            .get_results::<String>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let mut count = 0;
        for code in codes {
            assert!(codes_from_db.iter().any(|c| c == &code));
            count += 1;
        }

        assert_eq!(count, codes_from_db.len());

        let keystore = user_keystores
            .select(user_keystore_fields::encrypted_blob)
            .find(user.id)
            .get_result::<Vec<u8>>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(keystore, new_user.user_keystore_encrypted);

        let preferences = user_preferences
            .select(user_preferences_fields::encrypted_blob)
            .find(user.id)
            .get_result::<Vec<u8>>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(preferences, new_user.preferences_encrypted);

        assert!(
            dsl::select(dsl::exists(signin_nonces.find(&new_user.email)))
                .get_result::<bool>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
        );
    }

    #[actix_web::test]
    async fn test_verify_creation() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::from(env::testing::SMTP_THREAD_POOL.clone()))
                .configure(crate::services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: vec![8; 10],

            auth_string_salt: vec![8; 10],
            auth_string_memory_cost_kib: 1024,
            auth_string_parallelism_factor: 1,
            auth_string_iters: 2,

            password_encryption_salt: vec![8; 10],
            password_encryption_memory_cost_kib: 1024,
            password_encryption_parallelism_factor: 1,
            password_encryption_iters: 1,

            recovery_key_salt: vec![8; 10],
            recovery_key_memory_cost_kib: 1024,
            recovery_key_parallelism_factor: 1,
            recovery_key_iters: 1,

            encryption_key_encrypted_with_password: vec![8; 10],
            encryption_key_encrypted_with_recovery_key: vec![8; 10],

            public_key: vec![8; 10],

            preferences_encrypted: vec![8; 10],
            user_keystore_encrypted: vec![8; 10],
        };

        let req = TestRequest::post()
            .uri("/api/user/create")
            .insert_header(("AppVersion", "0.1.0"))
            .set_json(&new_user)
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let user = users
            .filter(user_fields::email.eq(&new_user.email))
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert!(!user.is_verified);

        let user_creation_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: SystemTime::now() + env::CONF.lifetimes.access_token_lifetime,
            token_type: AuthTokenType::UserCreation,
        };

        let user_creation_token = AuthToken::sign_new(
            user_creation_token_claims.encrypt(&env::CONF.keys.token_encryption_cipher),
            &env::CONF.keys.token_signing_key,
        );

        let req = TestRequest::get()
            .uri(&format!(
                "/api/user/verify_creation?UserCreationToken={}",
                &user_creation_token[..(user_creation_token.len() - 4)],
            ))
            .set_json(&new_user)
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let user = users
            .filter(user_fields::email.eq(&new_user.email))
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert!(!user.is_verified);

        let req = TestRequest::get()
            .uri(&format!(
                "/api/user/verify_creation?UserCreationToken={}",
                user_creation_token,
            ))
            .set_json(&new_user)
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let user = users
            .filter(user_fields::email.eq(&new_user.email))
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert!(user.is_verified);
    }

    #[actix_web::test]
    async fn test_edit_preferences() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::from(env::testing::SMTP_THREAD_POOL.clone()))
                .configure(crate::services::api::configure),
        )
        .await;

        let (user, access_token) = test_utils::create_user().await;

        let updated_prefs_blob: Vec<_> = (0..32)
            .map(|_| rand::thread_rng().gen_range(u8::MIN..u8::MAX))
            .collect();

        let updated_prefs = InputEditUserPrefs {
            encrypted_blob: updated_prefs_blob.clone(),
            expected_previous_data_hash: vec![200; 8],
        };

        let req = TestRequest::put()
            .uri("/api/user/edit_preferences")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("AppVersion", "0.1.0"))
            .set_json(&updated_prefs)
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = test::try_read_body(resp).await.unwrap();
        let resp_body = String::from_utf8_lossy(&resp_body);

        assert!(resp_body.contains("\"error_code\":\"U2SLOW\""));

        let stored_prefs_blob = user_preferences
            .select(user_preferences_fields::encrypted_blob)
            .find(user.id)
            .get_result::<Vec<u8>>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_ne!(stored_prefs_blob, updated_prefs_blob);

        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(&stored_prefs_blob);

        let updated_prefs = InputEditUserPrefs {
            encrypted_blob: updated_prefs_blob,
            expected_previous_data_hash: sha1_hasher.finalize().to_vec(),
        };

        let req = TestRequest::put()
            .uri("/api/user/edit_preferences")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("AppVersion", "0.1.0"))
            .set_json(&updated_prefs)
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let stored_prefs_blob = user_preferences
            .select(user_preferences_fields::encrypted_blob)
            .find(user.id)
            .get_result::<Vec<u8>>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(stored_prefs_blob, updated_prefs.encrypted_blob);
    }

    #[actix_web::test]
    async fn test_change_password() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::from(env::testing::SMTP_THREAD_POOL.clone()))
                .configure(crate::services::api::configure),
        )
        .await;

        let (user, access_token) = test_utils::create_user().await;

        // Make sure an OTP is generated
        let req = TestRequest::get()
            .uri("/api/auth/obtain_otp")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("AppVersion", "0.1.0"))
            .to_request();
        test::call_service(&app, req).await;

        let otp = user_otps
            .select(user_otp_fields::otp)
            .find(&user.email)
            .get_result::<String>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let updated_auth_string: Vec<_> = gen_bytes(32);
        let updated_auth_string_salt: Vec<_> = gen_bytes(16);
        let updated_password_encryption_salt: Vec<_> = gen_bytes(16);
        let updated_encrypted_encryption_key: Vec<_> = gen_bytes(48);

        let mut edit_password = InputNewAuthStringAndEncryptedPassword {
            user_email: user.email.clone(),
            otp: String::from("ABCDEFGH"),

            new_auth_string: updated_auth_string.clone(),

            auth_string_salt: updated_auth_string_salt.clone(),

            auth_string_memory_cost_kib: 11,
            auth_string_parallelism_factor: 13,
            auth_string_iters: 17,

            password_encryption_salt: updated_password_encryption_salt.clone(),

            password_encryption_memory_cost_kib: 13,
            password_encryption_parallelism_factor: 17,
            password_encryption_iters: 19,

            encrypted_encryption_key: updated_encrypted_encryption_key,
        };

        let req = TestRequest::put()
            .uri("/api/user/change_password")
            .insert_header(("AppVersion", "0.1.0"))
            .set_json(&edit_password)
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp_body = test::try_read_body(resp).await.unwrap();
        let resp_body = String::from_utf8_lossy(&resp_body);

        assert!(resp_body.contains("\"error_code\":\"DISNOU\""));

        let stored_user = users
            .find(user.id)
            .get_result::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert!(!argon2_kdf::Hash::from_str(&stored_user.auth_string_hash)
            .unwrap()
            .verify_with_secret(
                &edit_password.new_auth_string,
                argon2_kdf::Secret::using_bytes(&env::CONF.keys.hashing_key)
            ));

        assert_ne!(stored_user.auth_string_salt, edit_password.auth_string_salt);
        assert_ne!(
            stored_user.auth_string_memory_cost_kib,
            edit_password.auth_string_memory_cost_kib
        );
        assert_ne!(
            stored_user.auth_string_parallelism_factor,
            edit_password.auth_string_parallelism_factor
        );
        assert_ne!(
            stored_user.auth_string_iters,
            edit_password.auth_string_iters
        );

        assert_ne!(
            stored_user.password_encryption_salt,
            edit_password.password_encryption_salt
        );
        assert_ne!(
            stored_user.password_encryption_memory_cost_kib,
            edit_password.password_encryption_memory_cost_kib
        );
        assert_ne!(
            stored_user.password_encryption_parallelism_factor,
            edit_password.password_encryption_parallelism_factor
        );
        assert_ne!(
            stored_user.password_encryption_iters,
            edit_password.password_encryption_iters
        );

        assert_ne!(
            stored_user.encryption_key_encrypted_with_password,
            edit_password.encrypted_encryption_key
        );

        edit_password.otp = otp;

        let req = TestRequest::put()
            .uri("/api/user/change_password")
            .insert_header(("AppVersion", "0.1.0"))
            .set_json(&edit_password)
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let stored_user = users
            .find(user.id)
            .get_result::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert!(argon2_kdf::Hash::from_str(&stored_user.auth_string_hash)
            .unwrap()
            .verify_with_secret(
                &edit_password.new_auth_string,
                argon2_kdf::Secret::using_bytes(&env::CONF.keys.hashing_key)
            ));

        assert_eq!(stored_user.auth_string_salt, edit_password.auth_string_salt);
        assert_eq!(
            stored_user.auth_string_memory_cost_kib,
            edit_password.auth_string_memory_cost_kib
        );
        assert_eq!(
            stored_user.auth_string_parallelism_factor,
            edit_password.auth_string_parallelism_factor
        );
        assert_eq!(
            stored_user.auth_string_iters,
            edit_password.auth_string_iters
        );

        assert_eq!(
            stored_user.password_encryption_salt,
            edit_password.password_encryption_salt
        );
        assert_eq!(
            stored_user.password_encryption_memory_cost_kib,
            edit_password.password_encryption_memory_cost_kib
        );
        assert_eq!(
            stored_user.password_encryption_parallelism_factor,
            edit_password.password_encryption_parallelism_factor
        );
        assert_eq!(
            stored_user.password_encryption_iters,
            edit_password.password_encryption_iters
        );

        assert_eq!(
            stored_user.encryption_key_encrypted_with_password,
            edit_password.encrypted_encryption_key
        );

        let hash_start_pos = stored_user.auth_string_hash.rfind('$').unwrap() + 1;
        let hash_len: u32 = b64_nopad
            .decode(&stored_user.auth_string_hash[hash_start_pos..])
            .unwrap()
            .len()
            .try_into()
            .unwrap();

        assert_eq!(hash_len, env::CONF.hashing.hash_length);

        let salt_start_pos = (&stored_user.auth_string_hash[..(hash_start_pos - 1)])
            .rfind('$')
            .unwrap()
            + 1;
        let salt_end_pos = hash_start_pos - 1;
        let salt_len: u32 = b64_nopad
            .decode(&stored_user.auth_string_hash[salt_start_pos..salt_end_pos])
            .unwrap() //
            .len()
            .try_into()
            .unwrap();

        assert_eq!(salt_len, env::CONF.hashing.salt_length);

        assert!(stored_user.auth_string_hash.contains("argon2id"));
        assert!(stored_user
            .auth_string_hash
            .contains(&format!("m={}", env::CONF.hashing.hash_mem_cost_kib)));
        assert!(stored_user
            .auth_string_hash
            .contains(&format!("t={}", env::CONF.hashing.hash_iterations)));
        assert!(stored_user
            .auth_string_hash
            .contains(&format!("p={}", env::CONF.hashing.hash_threads)));
    }

    #[actix_web::test]
    async fn test_change_recovery_key() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::from(env::testing::SMTP_THREAD_POOL.clone()))
                .configure(crate::services::api::configure),
        )
        .await;

        let (user, access_token) = test_utils::create_user().await;

        // Make sure an OTP is generated
        let req = TestRequest::get()
            .uri("/api/auth/obtain_otp")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("AppVersion", "0.1.0"))
            .to_request();
        test::call_service(&app, req).await;

        let otp = user_otps
            .select(user_otp_fields::otp)
            .find(&user.email)
            .get_result::<String>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let updated_recovery_key_salt: Vec<_> = gen_bytes(16);
        let updated_encrypted_encryption_key: Vec<_> = gen_bytes(48);

        let mut edit_recovery_key = InputNewRecoveryKey {
            otp: String::from("ABCDEFGH"),

            recovery_key_salt: updated_recovery_key_salt.clone(),

            recovery_key_memory_cost_kib: 11,
            recovery_key_parallelism_factor: 13,
            recovery_key_iters: 17,

            encrypted_encryption_key: updated_encrypted_encryption_key,
        };

        let req = TestRequest::put()
            .uri("/api/user/change_recovery_key")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("AppVersion", "0.1.0"))
            .set_json(&edit_recovery_key)
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp_body = test::try_read_body(resp).await.unwrap();
        let resp_body = String::from_utf8_lossy(&resp_body);

        assert!(resp_body.contains("\"error_code\":\"DISNOU\""));

        edit_recovery_key.otp = otp;

        let req = TestRequest::put()
            .uri("/api/user/change_recovery_key")
            .insert_header(("AppVersion", "0.1.0"))
            .set_json(&edit_recovery_key)
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp_body = test::try_read_body(resp).await.unwrap();
        let resp_body = String::from_utf8_lossy(&resp_body);

        println!("\n\n{:#?}\n\n", resp_body);

        assert!(resp_body.contains("\"error_code\":\"UFORGT\""));

        let stored_user = users
            .find(user.id)
            .get_result::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_ne!(
            stored_user.recovery_key_salt,
            edit_recovery_key.recovery_key_salt
        );
        assert_ne!(
            stored_user.recovery_key_memory_cost_kib,
            edit_recovery_key.recovery_key_memory_cost_kib
        );
        assert_ne!(
            stored_user.recovery_key_parallelism_factor,
            edit_recovery_key.recovery_key_parallelism_factor
        );
        assert_ne!(
            stored_user.recovery_key_iters,
            edit_recovery_key.recovery_key_iters
        );
        assert_ne!(
            stored_user.encryption_key_encrypted_with_recovery_key,
            edit_recovery_key.encrypted_encryption_key
        );

        let req = TestRequest::put()
            .uri("/api/user/change_recovery_key")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("AppVersion", "0.1.0"))
            .set_json(&edit_recovery_key)
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let stored_user = users
            .find(user.id)
            .get_result::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(
            stored_user.recovery_key_salt,
            edit_recovery_key.recovery_key_salt
        );
        assert_eq!(
            stored_user.recovery_key_memory_cost_kib,
            edit_recovery_key.recovery_key_memory_cost_kib
        );
        assert_eq!(
            stored_user.recovery_key_parallelism_factor,
            edit_recovery_key.recovery_key_parallelism_factor
        );
        assert_eq!(
            stored_user.recovery_key_iters,
            edit_recovery_key.recovery_key_iters
        );
        assert_eq!(
            stored_user.encryption_key_encrypted_with_recovery_key,
            edit_recovery_key.encrypted_encryption_key
        );
    }

    #[actix_web::test]
    async fn test_delete_user_no_budgets() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::from(env::testing::SMTP_THREAD_POOL.clone()))
                .configure(crate::services::api::configure),
        )
        .await;

        // Test init_delete with no budget tokens
        let (user, access_token) = test_utils::create_user().await;

        let budget_access_tokens = InputBudgetAccessTokenList {
            budget_access_tokens: Vec::new(),
        };

        let req = TestRequest::delete()
            .uri("/api/user/init_delete")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("AppVersion", "0.1.0"))
            .set_json(budget_access_tokens)
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = test::read_body_json::<OutputVerificationEmailSent, _>(resp).await;
        assert!(resp_body.email_sent);

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);

        let deletion_request_budget_key_count = user_deletion_request_budget_keys
            .filter(user_deletion_request_budget_key_fields::user_id.eq(user.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_budget_key_count, 0);

        assert_eq!(
            users
                .filter(user_fields::id.eq(user.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        let user_deletion_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: SystemTime::now() + env::CONF.lifetimes.user_deletion_token_lifetime,
            token_type: AuthTokenType::UserDeletion,
        };

        let user_deletion_token = AuthToken::sign_new(
            user_deletion_token_claims.encrypt(&env::CONF.keys.token_encryption_cipher),
            &env::CONF.keys.token_signing_key,
        );

        let req = TestRequest::get()
            .uri(&format!(
                "/api/user/verify_deletion?{}={}",
                UserDeletion::token_name(),
                user_deletion_token,
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 1);

        let deletion_request_budget_key_count = user_deletion_request_budget_keys
            .filter(user_deletion_request_budget_key_fields::user_id.eq(user.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_budget_key_count, 0);

        assert_eq!(
            users
                .filter(user_fields::id.eq(user.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        let mut user_dao = db::user::Dao::new(&env::testing::DB_THREAD_POOL);
        user_dao.delete_user(&deletion_requests[0]).unwrap();

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);

        let deletion_request_budget_key_count = user_deletion_request_budget_keys
            .filter(user_deletion_request_budget_key_fields::user_id.eq(user.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_budget_key_count, 0);

        assert_eq!(
            users
                .filter(user_fields::id.eq(user.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );
    }

    #[actix_web::test]
    async fn test_delete_user_with_budgets() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::from(env::testing::SMTP_THREAD_POOL.clone()))
                .configure(crate::services::api::configure),
        )
        .await;

        // Test init_delete with no budget tokens
        let (user, access_token) = test_utils::create_user().await;

        let (budget1, budget1_token) = test_utils::create_budget(&access_token).await;
        let (budget2, budget2_token) = test_utils::create_budget(&access_token).await;

        let budget_access_tokens = InputBudgetAccessTokenList {
            budget_access_tokens: vec![budget1_token, budget2_token],
        };

        let req = TestRequest::delete()
            .uri("/api/user/init_delete")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("AppVersion", "0.1.0"))
            .set_json(budget_access_tokens)
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = test::read_body_json::<OutputVerificationEmailSent, _>(resp).await;
        assert!(resp_body.email_sent);

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);

        let deletion_request_budget_key_count = user_deletion_request_budget_keys
            .filter(user_deletion_request_budget_key_fields::user_id.eq(user.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_budget_key_count, 2);

        assert_eq!(
            users
                .filter(user_fields::id.eq(user.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        // TODO: Check budget_access_keys
        // TODO: Check budgets

        let user_deletion_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: SystemTime::now() + env::CONF.lifetimes.user_deletion_token_lifetime,
            token_type: AuthTokenType::UserDeletion,
        };

        let user_deletion_token = AuthToken::sign_new(
            user_deletion_token_claims.encrypt(&env::CONF.keys.token_encryption_cipher),
            &env::CONF.keys.token_signing_key,
        );

        let req = TestRequest::get()
            .uri(&format!(
                "/api/user/verify_deletion?{}={}",
                UserDeletion::token_name(),
                user_deletion_token,
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 1);

        let deletion_request_budget_key_count = user_deletion_request_budget_keys
            .filter(user_deletion_request_budget_key_fields::user_id.eq(user.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_budget_key_count, 2);

        assert_eq!(
            users
                .filter(user_fields::id.eq(user.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        // TODO: Check budget_access_keys
        // TODO: Check budgets

        let mut user_dao = db::user::Dao::new(&env::testing::DB_THREAD_POOL);
        user_dao.delete_user(&deletion_requests[0]).unwrap();

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);

        let deletion_request_budget_key_count = user_deletion_request_budget_keys
            .filter(user_deletion_request_budget_key_fields::user_id.eq(user.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_budget_key_count, 0);

        assert_eq!(
            users
                .filter(user_fields::id.eq(user.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );

        // TODO: Check budget_access_keys
        // TODO: Check budgets

        // TODO: Test wrong token causes a 403
        // TODO: Test with a shared token (delete just one user, budget should survive) and an unshared token
        // TODO: Test with a shared token (delete both users, budget should be deleted)

        todo!();
    }
}
