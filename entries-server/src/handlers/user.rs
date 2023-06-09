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
use entries_utils::token::auth_token::{AuthToken, AuthTokenType};
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

    let mut user_creation_token = AuthToken::new(
        user_id,
        &user_data.email,
        SystemTime::now() + env::CONF.lifetimes.user_creation_token_lifetime,
        AuthTokenType::UserCreation,
    );

    user_creation_token.encrypt(&env::CONF.keys.token_encryption_cipher);
    let user_creation_token =
        user_creation_token.sign_and_encode(&env::CONF.keys.token_signing_key);

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
            return Ok(HttpResponse::BadRequest()
                .content_type("text/html")
                .body(VerifyUserExpiredLinkPage::generate()));
        }
        Err(TokenError::TokenMissing) => {
            return Ok(HttpResponse::BadRequest()
                .content_type("text/html")
                .body(VerifyUserLinkMissingTokenPage::generate()));
        }
        Err(TokenError::WrongTokenType) | Err(TokenError::TokenInvalid) => {
            return Ok(HttpResponse::BadRequest()
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
    const INVALID_ID_MSG: &str = "One of the provided budget access tokens had an invalid ID";

    let mut tokens = HashMap::new();
    let mut key_ids = Vec::new();
    let mut budget_ids = Vec::new();

    for token in budget_access_tokens.budget_access_tokens.iter() {
        let token = match BudgetAccessToken::from_str(token) {
            Ok(t) => t,
            Err(_) => return Err(HttpErrorResponse::IncorrectlyFormed(INVALID_ID_MSG)),
        };

        key_ids.push(token.key_id());
        budget_ids.push(token.budget_id());
        tokens.insert(token.key_id(), token);
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

        if !token.verify(&key.public_key) {
            return Err(HttpErrorResponse::DoesNotExist(INVALID_ID_MSG));
        }
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

    let mut user_deletion_token = AuthToken::new(
        user_access_token.0.user_id,
        &user_access_token.0.user_email,
        deletion_token_expiration,
        AuthTokenType::UserDeletion,
    );

    user_deletion_token.encrypt(&env::CONF.keys.token_encryption_cipher);
    let user_deletion_token =
        user_deletion_token.sign_and_encode(&env::CONF.keys.token_signing_key);

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

    Ok(HttpResponse::Created().json(OutputVerificationEmailSent {
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

    use entries_utils::request_io::InputUser;

    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::web::Data;
    use actix_web::App;
    use rand::Rng;

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

            auth_string: Vec::new(),

            auth_string_salt: Vec::new(),
            auth_string_memory_cost_kib: 1024,
            auth_string_parallelism_factor: 1,
            auth_string_iters: 2,

            password_encryption_salt: Vec::new(),
            password_encryption_memory_cost_kib: 1024,
            password_encryption_parallelism_factor: 1,
            password_encryption_iters: 1,

            recovery_key_salt: Vec::new(),
            recovery_key_memory_cost_kib: 1024,
            recovery_key_parallelism_factor: 1,
            recovery_key_iters: 1,

            encryption_key_encrypted_with_password: Vec::new(),
            encryption_key_encrypted_with_recovery_key: Vec::new(),

            public_key: Vec::new(),

            preferences_encrypted: Vec::new(),
            user_keystore_encrypted: Vec::new(),

            acknowledge_agreement: true,
        };

        let req = TestRequest::post()
            .uri("/api/user/create")
            .insert_header(("AppVersion", "0.1.0"))
            .set_json(&new_user)
            .to_request();
        let resp = test::call_service(&app, req).await;

        println!(
            "body: {}",
            String::from_utf8_lossy(&actix_web::test::try_read_body(resp).await.unwrap())
        );
        // assert_eq!(resp.status(), StatusCode::CREATED);

        todo!();
    }
}
