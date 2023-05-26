use entries_utils::db::{DaoError, DbThreadPool};
use entries_utils::email::templates::UserVerificationMessage;
use entries_utils::email::{EmailMessage, EmailSender};
use entries_utils::html::templates::{
    DeleteUserAccountNotFoundPage, DeleteUserAlreadyScheduledPage, DeleteUserExpiredLinkPage,
    DeleteUserInternalErrorPage, DeleteUserInvalidLinkPage, DeleteUserLinkMissingTokenPage,
    DeleteUserSuccessPage, VerifyUserAccountNotFoundPage, VerifyUserExpiredLinkPage,
    VerifyUserInternalErrorPage, VerifyUserInvalidLinkPage, VerifyUserLinkMissingTokenPage,
    VerifyUserSuccessPage,
};
use entries_utils::request_io::{
    InputBudgetAccessTokenList, InputEditUserKeystore, InputEditUserPrefs, InputEmail,
    InputNewAuthStringAndEncryptedPassword, InputUser, OutputIsUserListedForDeletion,
    OutputPublicKey, OutputVerificationEmailSent,
};
use entries_utils::token::auth_token::{AuthToken, AuthTokenType};
use entries_utils::token::budget_access_token::BudgetAccessToken;
use entries_utils::token::{Token, TokenError};
use entries_utils::validators::{self, Validity};
use entries_utils::{argon2, db};

use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::oneshot;

use crate::env;
use crate::handlers::error::HttpErrorResponse;
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
    app_version: AppVersion,
    user_data: web::Json<InputUser>,
    throttle: Throttle<5, 5>,
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
        let hash = argon2::hash_auth_string(
            &user_data_ref.auth_string,
            &argon2::HashParams {
                salt_len: env::CONF.hashing.salt_length_bytes,
                hash_len: env::CONF.hashing.hash_length,
                hash_iterations: env::CONF.hashing.hash_iterations,
                hash_mem_size_kib: env::CONF.hashing.hash_mem_size_kib,
                hash_lanes: env::CONF.hashing.hash_lanes,
            },
            &env::CONF.keys.hashing_key,
        );

        sender.send(hash).expect("Sending to channel failed");
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

    let user_data_ref = Arc::clone(&user_data);

    let user_id = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.create_user(&user_data_ref.0, &app_version.0, &auth_string_hash)
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

    Ok(HttpResponse::Created().json(OutputVerificationEmailSent {
        email_sent: true,
        email_token_lifetime_hours: env::CONF.lifetimes.user_creation_token_lifetime.as_secs()
            / 3600,
    }))
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
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                log::error!(
                    "Failed to verify user after validating UserCreationToken: {}",
                    e
                );
                return Ok(HttpResponse::BadRequest()
                    .content_type("text/html")
                    .body(VerifyUserAccountNotFoundPage::generate()));
            }
            _ => {
                log::error!("{e}");
                return Ok(HttpResponse::InternalServerError()
                    .content_type("text/html")
                    .body(VerifyUserInternalErrorPage::generate()));
            }
        },
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
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist("No user with provided ID"));
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
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist("No user with provided ID"));
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
    user_access_token: VerifiedToken<Access, FromHeader>,
    new_password_data: web::Json<InputNewAuthStringAndEncryptedPassword>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
    let current_auth_string = new_password_data.current_auth_string.clone();
    let user_id = user_access_token.0.user_id;

    if new_password_data.current_auth_string.len() > 512
        || new_password_data.new_auth_string.len() > 512
    {
        return Err(HttpErrorResponse::InputTooLong(
            "Provided password is too long. Max: 512 bytes",
        ));
    }

    let hash = match web::block(move || {
        auth_dao.get_user_auth_string_hash_and_status(&user_access_token.0.user_email)
    })
    .await?
    {
        Ok(a) => a,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(
                "Failed to get user auth string",
            ));
        }
    };

    let (sender, receiver) = oneshot::channel();

    rayon::spawn(move || {
        let does_current_auth_match = argon2::verify_hash(
            &current_auth_string,
            &hash.auth_string_hash,
            &env::CONF.keys.hashing_key,
        );

        sender
            .send(does_current_auth_match)
            .expect("Sending to channel failed");
    });

    if !receiver.await? {
        return Err(HttpErrorResponse::IncorrectCredential(
            "Current auth string was incorrect",
        ));
    }

    web::block(move || {
        let _auth_string_hash = {
            argon2::hash_auth_string(
                &new_password_data.new_auth_string,
                &argon2::HashParams {
                    salt_len: env::CONF.hashing.salt_length_bytes,
                    hash_len: env::CONF.hashing.hash_length,
                    hash_iterations: env::CONF.hashing.hash_iterations,
                    hash_mem_size_kib: env::CONF.hashing.hash_mem_size_kib,
                    hash_lanes: env::CONF.hashing.hash_lanes,
                },
                &env::CONF.keys.hashing_key,
            )
        };

        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.update_password(
            user_id,
            &new_password_data.0.new_auth_string,
            &new_password_data.0.auth_string_salt,
            new_password_data.0.auth_string_iters,
            &new_password_data.0.encrypted_encryption_key,
        )
    })
    .await
    .map(|_| HttpResponse::Ok().finish())
    .map_err(|e| {
        log::error!("{e}");
        HttpErrorResponse::InternalError("Failed to update password")
    })
}

// TODO: Initiate reset password by sending an email with a code ("forgot password")
// TODO: This endpoint should be debounced and not send more than one email to a given address
//       per minute

pub async fn init_delete(
    db_thread_pool: web::Data<DbThreadPool>,
    smtp_thread_pool: web::Data<EmailSender>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_tokens: web::Data<InputBudgetAccessTokenList>,
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
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist("No user with provided ID"));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(
                    "Failed to cancel user deletion",
                ));
            }
        },
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
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist("No user with provided ID"));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(
                    "Failed to cancel user deletion",
                ));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}
