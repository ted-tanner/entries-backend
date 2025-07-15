use entries_common::db::{self, DaoError, DbThreadPool};
use entries_common::email::templates::UserVerificationMessage;
use entries_common::email::{EmailMessage, EmailSender};
use entries_common::html::templates::{
    DeleteUserAccountNotFoundPage, DeleteUserAlreadyScheduledPage, DeleteUserExpiredLinkPage,
    DeleteUserInternalErrorPage, DeleteUserInvalidLinkPage, DeleteUserLinkMissingTokenPage,
    DeleteUserSuccessPage, VerifyUserExpiredLinkPage, VerifyUserInternalErrorPage,
    VerifyUserInvalidLinkPage, VerifyUserLinkMissingTokenPage, VerifyUserSuccessPage,
};
use entries_common::messages::{
    AuthStringAndEncryptedPasswordUpdate, ContainerAccessTokenList, EmailChangeRequest, EmailQuery,
    EncryptedBlobUpdate, IsUserListedForDeletion, NewUser, NewUserPublicKey, RecoveryKeyUpdate,
    UserPublicKey, VerificationEmailSent,
};
use entries_common::token::auth_token::{AuthToken, AuthTokenType, NewAuthTokenClaims};
use entries_common::token::container_access_token::ContainerAccessToken;
use entries_common::token::{Token, TokenError};
use entries_common::validators::{self, Validity};

use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
use actix_web::{web, HttpResponse};
use futures::future;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;

use crate::env;
use crate::handlers::{self, error::DoesNotExistType, error::HttpErrorResponse};
use crate::middleware::auth::{Access, UnverifiedToken, UserCreation, UserDeletion, VerifiedToken};
use crate::middleware::{FromHeader, FromQuery};

pub async fn lookup_user_public_key(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    user_email: web::Query<EmailQuery>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let (key_id, key) = match web::block(move || {
        let user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.get_user_public_key(&user_email.email)
    })
    .await?
    {
        Ok(k) => (k.id, k.value),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("No user with given email address"),
                    DoesNotExistType::Key,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to get user's public key",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().protobuf(UserPublicKey {
        id: key_id,
        value: key,
    })?)
}

pub async fn create(
    db_thread_pool: web::Data<DbThreadPool>,
    smtp_thread_pool: web::Data<EmailSender>,
    user_data: ProtoBuf<NewUser>,
) -> Result<HttpResponse, HttpErrorResponse> {
    if let Validity::Invalid(msg) = validators::validate_email_address(&user_data.0.email) {
        return Err(HttpErrorResponse::IncorrectlyFormed(String::from(msg)));
    }

    if user_data.0.auth_string.len() > env::CONF.max_auth_string_length {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Auth string is too long",
        )));
    }

    if user_data.0.auth_string_hash_salt.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Auth string salt is too big",
        )));
    }

    if user_data.0.password_encryption_key_salt.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Password encryption salt is too big",
        )));
    }

    if user_data.0.recovery_key_hash_salt_for_encryption.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Recovery key salt for encryption is too big",
        )));
    }

    if user_data.0.recovery_key_hash_salt_for_recovery_auth.len()
        > env::CONF.max_encryption_key_size
    {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Recovery key salt for recovery auth is too big",
        )));
    }

    if user_data.0.recovery_key_auth_hash.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Recovery key auth hash is too long",
        )));
    }

    if user_data.0.encryption_key_encrypted_with_password.len() > env::CONF.max_encryption_key_size
    {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Encryption key encrypted with password is too big",
        )));
    }

    if user_data.0.encryption_key_encrypted_with_recovery_key.len()
        > env::CONF.max_encryption_key_size
    {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Encryption key encrypted with recovery key is too big",
        )));
    }

    if user_data.0.public_key.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Public key is too big",
        )));
    }

    if user_data.0.preferences_encrypted.len() > env::CONF.max_user_preferences_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Preferences encrypted is too big",
        )));
    }

    if user_data.0.user_keystore_encrypted.len() > env::CONF.max_keystore_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "User keystore encrypted is too big",
        )));
    }

    let user_data = Arc::new(user_data.0);
    let user_data_ref1 = Arc::clone(&user_data);
    let user_data_ref2 = Arc::clone(&user_data);

    let (sender_auth_string, receiver_auth_string) = oneshot::channel();
    let (sender_recovery_key, receiver_recovery_key) = oneshot::channel();

    // Hash auth string
    rayon::spawn(move || {
        let hash_result = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.auth_string_hash_salt_length)
            .hash_length(env::CONF.auth_string_hash_length)
            .iterations(env::CONF.auth_string_hash_iterations)
            .memory_cost_kib(env::CONF.auth_string_hash_mem_cost_kib)
            .threads(env::CONF.auth_string_hash_threads)
            .secret((&env::CONF.auth_string_hash_key).into())
            .hash(&user_data_ref1.auth_string);

        let hash = match hash_result {
            Ok(h) => h,
            Err(e) => {
                sender_auth_string
                    .send(Err(e))
                    .expect("Sending to channel failed");
                return;
            }
        };

        sender_auth_string
            .send(Ok(hash.to_string()))
            .expect("Sending to channel failed");
    });

    // Hash recovery key auth hash
    rayon::spawn(move || {
        let hash_result = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.auth_string_hash_salt_length)
            .hash_length(env::CONF.auth_string_hash_length)
            .iterations(env::CONF.auth_string_hash_iterations)
            .memory_cost_kib(env::CONF.auth_string_hash_mem_cost_kib)
            .threads(env::CONF.auth_string_hash_threads)
            .secret((&env::CONF.auth_string_hash_key).into())
            .hash(&user_data_ref2.recovery_key_auth_hash);

        let hash = match hash_result {
            Ok(h) => h,
            Err(e) => {
                sender_recovery_key
                    .send(Err(e))
                    .expect("Sending to channel failed");
                return;
            }
        };

        sender_recovery_key
            .send(Ok(hash.to_string()))
            .expect("Sending to channel failed");
    });

    let (auth_string_hash, recovery_key_rehashed) =
        future::join(receiver_auth_string, receiver_recovery_key).await;

    let auth_string_hash = match auth_string_hash? {
        Ok(s) => s,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to hash auth atring",
            )));
        }
    };

    let recovery_key_rehashed = match recovery_key_rehashed? {
        Ok(s) => s,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to rehash recovery key auth hash",
            )));
        }
    };

    let user_public_key_id = (&user_data.public_key_id).try_into()?;
    let user_data_ref = Arc::clone(&user_data);

    let user_id = match web::block(move || {
        let user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.create_user(
            &user_data_ref.email,
            &auth_string_hash,
            &user_data_ref.auth_string_hash_salt,
            user_data_ref.auth_string_hash_mem_cost_kib,
            user_data_ref.auth_string_hash_threads,
            user_data_ref.auth_string_hash_iterations,
            &user_data_ref.password_encryption_key_salt,
            user_data_ref.password_encryption_key_mem_cost_kib,
            user_data_ref.password_encryption_key_threads,
            user_data_ref.password_encryption_key_iterations,
            &user_data_ref.recovery_key_hash_salt_for_encryption,
            &user_data_ref.recovery_key_hash_salt_for_recovery_auth,
            user_data_ref.recovery_key_hash_mem_cost_kib,
            user_data_ref.recovery_key_hash_threads,
            user_data_ref.recovery_key_hash_iterations,
            &recovery_key_rehashed,
            &user_data_ref.encryption_key_encrypted_with_password,
            &user_data_ref.encryption_key_encrypted_with_recovery_key,
            user_public_key_id,
            &user_data_ref.public_key,
            &user_data_ref.preferences_encrypted,
            user_data_ref.preferences_version_nonce,
            &user_data_ref.user_keystore_encrypted,
            user_data_ref.user_keystore_version_nonce,
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
                return Err(HttpErrorResponse::ConflictWithExisting(String::from(
                    "A user with the given email address already exists",
                )));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to create user",
                )));
            }
        },
    };

    let user_creation_token_claims = NewAuthTokenClaims {
        user_id,
        user_email: &user_data.email,
        expiration: (SystemTime::now() + env::CONF.user_creation_token_lifetime)
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
        destination: &user_data.email,
        is_html: true,
    };

    match smtp_thread_pool.send(message).await {
        Ok(_) => (),
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to send user verification token to user's email address",
            )));
        }
    };

    let resp_body = HttpResponse::Created().protobuf(VerificationEmailSent {
        email_sent: true,
        email_token_lifetime_hours: env::CONF.user_creation_token_lifetime.as_secs() / 3600,
    })?;

    Ok(resp_body)
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
        let user_dao = db::user::Dao::new(&db_thread_pool);
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

pub async fn rotate_user_public_key(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    new_key: ProtoBuf<NewUserPublicKey>,
) -> Result<HttpResponse, HttpErrorResponse> {
    if new_key.value.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "User public key is too long",
        )));
    }

    let new_key_id = (&new_key.0.id).try_into()?;
    let expected_previous_public_key_id =
        (&new_key.0.expected_previous_public_key_id).try_into()?;
    match web::block(move || {
        let user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.rotate_user_public_key(
            user_access_token.0.user_id,
            new_key_id,
            &new_key.0.value,
            expected_previous_public_key_id,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(DaoError::OutOfDate) => {
            return Err(HttpErrorResponse::OutOfDate(String::from(
                "Expected key was out of date",
            )));
        }
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to rotate user public key",
            )));
        }
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn edit_preferences(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    new_prefs: ProtoBuf<EncryptedBlobUpdate>,
) -> Result<HttpResponse, HttpErrorResponse> {
    if new_prefs.encrypted_blob.len() > env::CONF.max_user_preferences_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "User preferences are too large",
        )));
    }

    match web::block(move || {
        let user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.update_user_prefs(
            user_access_token.0.user_id,
            &new_prefs.encrypted_blob,
            new_prefs.version_nonce,
            new_prefs.expected_previous_version_nonce,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::OutOfDate => {
                return Err(HttpErrorResponse::OutOfDate(String::from(
                    "Out of date version nonce",
                )));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to update user preferences",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn edit_keystore(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    new_keystore: ProtoBuf<EncryptedBlobUpdate>,
) -> Result<HttpResponse, HttpErrorResponse> {
    if new_keystore.encrypted_blob.len() > env::CONF.max_keystore_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "User keystore is too large",
        )));
    }

    match web::block(move || {
        let user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.update_user_keystore(
            user_access_token.0.user_id,
            &new_keystore.encrypted_blob,
            new_keystore.version_nonce,
            new_keystore.expected_previous_version_nonce,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::OutOfDate => {
                return Err(HttpErrorResponse::OutOfDate(String::from(
                    "Out of date version nonce",
                )));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to update user keystore",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn change_password(
    db_thread_pool: web::Data<DbThreadPool>,
    new_password_data: ProtoBuf<AuthStringAndEncryptedPasswordUpdate>,
) -> Result<HttpResponse, HttpErrorResponse> {
    if new_password_data.0.new_auth_string.len() > env::CONF.max_auth_string_length {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Auth string is too long",
        )));
    }

    if new_password_data.0.auth_string_hash_salt.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Auth string salt is too long",
        )));
    }

    if new_password_data.0.password_encryption_key_salt.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Password encryption salt is too long",
        )));
    }

    if new_password_data.0.encrypted_encryption_key.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Encrypted encryption key is too long",
        )));
    }

    handlers::verification::verify_otp(
        &new_password_data.0.otp,
        &new_password_data.0.user_email,
        &db_thread_pool,
    )
    .await?;

    let new_password_data = Arc::new(new_password_data.0);
    let new_password_data_ref = Arc::clone(&new_password_data);

    let (sender, receiver) = oneshot::channel();

    rayon::spawn(move || {
        let hash_result = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.auth_string_hash_salt_length)
            .hash_length(env::CONF.auth_string_hash_length)
            .iterations(env::CONF.auth_string_hash_iterations)
            .memory_cost_kib(env::CONF.auth_string_hash_mem_cost_kib)
            .threads(env::CONF.auth_string_hash_threads)
            .secret((&env::CONF.auth_string_hash_key).into())
            .hash(&new_password_data_ref.new_auth_string);

        let hash = match hash_result {
            Ok(h) => h,
            Err(e) => {
                sender.send(Err(e)).expect("Sending to channel failed");
                return;
            }
        };

        sender
            .send(Ok(hash.to_string()))
            .expect("Sending to channel failed");
    });

    let auth_string_hash = match receiver.await? {
        Ok(s) => s,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to hash auth atring",
            )));
        }
    };

    web::block(move || {
        let user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.update_password(
            &new_password_data.user_email,
            &auth_string_hash,
            &new_password_data.auth_string_hash_salt,
            new_password_data.auth_string_hash_mem_cost_kib,
            new_password_data.auth_string_hash_threads,
            new_password_data.auth_string_hash_iterations,
            &new_password_data.password_encryption_key_salt,
            new_password_data.password_encryption_key_mem_cost_kib,
            new_password_data.password_encryption_key_threads,
            new_password_data.password_encryption_key_iterations,
            &new_password_data.encrypted_encryption_key,
        )
    })
    .await
    .map(|_| HttpResponse::Ok().finish())
    .map_err(|e| {
        log::error!("{e}");
        HttpErrorResponse::InternalError(String::from("Failed to update password"))
    })
}

pub async fn change_recovery_key(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    new_recovery_key_data: ProtoBuf<RecoveryKeyUpdate>,
) -> Result<HttpResponse, HttpErrorResponse> {
    if new_recovery_key_data
        .recovery_key_hash_salt_for_encryption
        .len()
        > env::CONF.max_encryption_key_size
    {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Recovery key salt for encryption is too long",
        )));
    }

    if new_recovery_key_data
        .recovery_key_hash_salt_for_recovery_auth
        .len()
        > env::CONF.max_encryption_key_size
    {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Recovery key salt for recovery auth is too long",
        )));
    }

    if new_recovery_key_data.recovery_key_auth_hash.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Recovery key auth hash is too long",
        )));
    }

    if new_recovery_key_data.encrypted_encryption_key.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Encrypted encryption key is too long",
        )));
    }

    let user_id = user_access_token.0.user_id;

    handlers::verification::verify_otp(
        &new_recovery_key_data.otp,
        &user_access_token.0.user_email,
        &db_thread_pool,
    )
    .await?;

    // Rehash recovery key auth hash for storage
    let new_recovery_key_data = Arc::new(new_recovery_key_data);
    let new_recovery_key_ref = Arc::clone(&new_recovery_key_data);

    let (sender, receiver) = oneshot::channel();

    rayon::spawn(move || {
        let hash_result = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.auth_string_hash_salt_length)
            .hash_length(env::CONF.auth_string_hash_length)
            .iterations(env::CONF.auth_string_hash_iterations)
            .memory_cost_kib(env::CONF.auth_string_hash_mem_cost_kib)
            .threads(env::CONF.auth_string_hash_threads)
            .secret((&env::CONF.auth_string_hash_key).into())
            .hash(&new_recovery_key_ref.recovery_key_auth_hash);

        let hash = match hash_result {
            Ok(h) => h,
            Err(e) => {
                sender.send(Err(e)).expect("Sending to channel failed");
                return;
            }
        };

        sender
            .send(Ok(hash.to_string()))
            .expect("Sending to channel failed");
    });

    let rehashed_recovery_key_auth_hash = match receiver.await? {
        Ok(s) => s,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to rehash recovery key auth hash",
            )));
        }
    };

    match web::block(move || {
        let user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.update_recovery_key(
            user_id,
            &new_recovery_key_data.recovery_key_hash_salt_for_encryption,
            &new_recovery_key_data.recovery_key_hash_salt_for_recovery_auth,
            new_recovery_key_data.recovery_key_hash_mem_cost_kib,
            new_recovery_key_data.recovery_key_hash_threads,
            new_recovery_key_data.recovery_key_hash_iterations,
            &rehashed_recovery_key_auth_hash,
            &new_recovery_key_data.encrypted_encryption_key,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to update recovery key",
            )));
        }
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn change_email(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    email_change_data: ProtoBuf<EmailChangeRequest>,
) -> Result<HttpResponse, HttpErrorResponse> {
    if let Validity::Invalid(msg) =
        validators::validate_email_address(&email_change_data.0.new_email)
    {
        return Err(HttpErrorResponse::IncorrectlyFormed(String::from(msg)));
    }

    handlers::verification::verify_auth_string(
        &email_change_data.0.auth_string,
        &user_access_token.0.user_email,
        false,
        &db_thread_pool,
    )
    .await?;

    // Check if the new email is already in use
    let new_email = email_change_data.0.new_email.clone();
    let db_thread_pool_check = db_thread_pool.clone();
    let new_email_exists = web::block(move || {
        let user_dao = db::user::Dao::new(&db_thread_pool_check);

        // All users have a public key, so if we can't find one, the email doesn't exist
        match user_dao.get_user_public_key(&new_email) {
            Ok(_) => Ok(true), // Email exists
            Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => Ok(false),
            Err(e) => Err(e),
        }
    })
    .await?;

    let new_email_exists = match new_email_exists {
        Ok(b) => b,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to check if email exists",
            )));
        }
    };

    if new_email_exists {
        return Err(HttpErrorResponse::ConflictWithExisting(String::from(
            "A user with the given email address already exists",
        )));
    }

    let new_email = email_change_data.new_email.clone();
    let user_id = user_access_token.0.user_id;
    let db_thread_pool_update = db_thread_pool.clone();
    match web::block(move || {
        let user_dao = db::user::Dao::new(&db_thread_pool_update);
        user_dao.update_email(user_id, &new_email)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to update email",
            )));
        }
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn init_delete(
    db_thread_pool: web::Data<DbThreadPool>,
    smtp_thread_pool: web::Data<EmailSender>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    container_access_tokens: ProtoBuf<ContainerAccessTokenList>,
) -> Result<HttpResponse, HttpErrorResponse> {
    const INVALID_ID_MSG: &str =
        "One of the provided container access tokens is invalid or has an incorrect ID";

    if container_access_tokens.tokens.len() > env::CONF.max_containers {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Too many container access tokens",
        )));
    }

    let mut tokens = HashMap::new();
    let mut key_ids = Vec::new();
    let mut container_ids = Vec::new();

    for token in container_access_tokens.tokens.iter() {
        let token = ContainerAccessToken::decode(token)
            .map_err(|_| HttpErrorResponse::IncorrectlyFormed(String::from(INVALID_ID_MSG)))?;

        key_ids.push(token.claims.key_id);
        container_ids.push(token.claims.container_id);
        tokens.insert(token.claims.key_id, token);
    }

    let key_ids = Arc::new(key_ids);
    let key_ids_ref = Arc::clone(&key_ids);

    let container_dao = db::container::Dao::new(&db_thread_pool);
    let public_keys = match web::block(move || {
        container_dao.get_multiple_public_container_keys(&key_ids_ref, &container_ids)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from(INVALID_ID_MSG),
                    DoesNotExistType::Container,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to get container data corresponding to container access token",
                )));
            }
        },
    };

    if public_keys.len() != tokens.len() {
        return Err(HttpErrorResponse::DoesNotExist(
            String::from(INVALID_ID_MSG),
            DoesNotExistType::Container,
        ));
    }

    for key in public_keys {
        let token = match tokens.get(&key.key_id) {
            Some(t) => t,
            None => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from(INVALID_ID_MSG),
                    DoesNotExistType::Container,
                ))
            }
        };

        token.verify(&key.public_key)?;
    }

    let deletion_token_expiration = SystemTime::now() + env::CONF.user_deletion_token_lifetime;
    let delete_me_time = deletion_token_expiration
        + Duration::from_secs(env::CONF.user_deletion_delay_days * 24 * 3600);

    let user_id = user_access_token.0.user_id;

    match web::block(move || {
        let user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.save_user_deletion_container_keys(&key_ids, user_id, delete_me_time)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from(INVALID_ID_MSG),
                    DoesNotExistType::User,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to save user deletion container keys",
                )));
            }
        },
    }

    let user_deletion_token_claims = NewAuthTokenClaims {
        user_id: user_access_token.0.user_id,
        user_email: &user_access_token.0.user_email,
        expiration: (SystemTime::now() + env::CONF.user_deletion_token_lifetime)
            .duration_since(UNIX_EPOCH)
            .expect("System time should be after Unix Epoch")
            .as_secs(),
        token_type: AuthTokenType::UserDeletion,
    };

    let user_deletion_token =
        AuthToken::sign_new(user_deletion_token_claims, &env::CONF.token_signing_key);

    let message = EmailMessage {
        body: UserVerificationMessage::generate(
            &env::CONF.user_deletion_url,
            &user_deletion_token,
            env::CONF.user_deletion_token_lifetime,
        ),
        subject: "Confirm the deletion of your Entries App account",
        from: env::CONF.email_from_address.clone(),
        reply_to: env::CONF.email_reply_to_address.clone(),
        destination: &user_access_token.0.user_email,
        is_html: true,
    };

    match smtp_thread_pool.send(message).await {
        Ok(_) => (),
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to send user deletion token to user's email address",
            )));
        }
    };

    Ok(HttpResponse::Ok().protobuf(VerificationEmailSent {
        email_sent: true,
        email_token_lifetime_hours: env::CONF.user_deletion_token_lifetime.as_secs() / 3600,
    })?)
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
    let days_until_deletion = env::CONF.user_deletion_delay_days;

    match web::block(move || {
        let user_dao = db::user::Dao::new(&db_thread_pool);
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
        let user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.check_is_user_listed_for_deletion(user_access_token.0.user_id)
    })
    .await?
    {
        Ok(l) => l,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to cancel user deletion",
            )));
        }
    };

    Ok(HttpResponse::Ok().protobuf(IsUserListedForDeletion {
        value: is_listed_for_deletion,
    })?)
}

pub async fn cancel_delete(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    match web::block(move || {
        let user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.cancel_user_deletion(user_access_token.0.user_id)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to cancel user deletion",
            )));
        }
    };

    Ok(HttpResponse::Ok().finish())
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use entries_common::messages::{
        EntryAndCategory, EntryIdAndCategoryId, ErrorType, NewUser, ServerErrorResponse,
        Uuid as UuidMessage,
    };
    use entries_common::models::user::User;
    use entries_common::models::user_deletion_request::UserDeletionRequest;
    use entries_common::schema::container_access_keys as container_access_key_fields;
    use entries_common::schema::container_access_keys::dsl::container_access_keys;
    use entries_common::schema::containers as container_fields;
    use entries_common::schema::containers::dsl::containers;
    use entries_common::schema::categories as category_fields;
    use entries_common::schema::categories::dsl::categories;
    use entries_common::schema::entries as entry_fields;
    use entries_common::schema::entries::dsl::entries;
    use entries_common::schema::signin_nonces::dsl::signin_nonces;
    use entries_common::schema::user_deletion_request_container_keys as user_deletion_request_container_key_fields;
    use entries_common::schema::user_deletion_request_container_keys::dsl::user_deletion_request_container_keys;
    use entries_common::schema::user_deletion_requests as user_deletion_request_fields;
    use entries_common::schema::user_deletion_requests::dsl::user_deletion_requests;
    use entries_common::schema::user_keystores as user_keystore_fields;
    use entries_common::schema::user_keystores::dsl::user_keystores;
    use entries_common::schema::user_otps as user_otp_fields;
    use entries_common::schema::user_otps::dsl::user_otps;
    use entries_common::schema::user_preferences as user_preferences_fields;
    use entries_common::schema::user_preferences::dsl::user_preferences;
    use entries_common::schema::users as user_fields;
    use entries_common::schema::users::dsl::users;
    use entries_common::threadrand::SecureRng;
    use entries_common::token::container_access_token::ContainerAccessTokenClaims;

    use actix_protobuf::ProtoBufConfig;
    use actix_web::body::to_bytes;
    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::web::Data;
    use actix_web::App;
    use base64::engine::general_purpose::STANDARD_NO_PAD as b64_nopad;
    use base64::engine::general_purpose::URL_SAFE as b64_urlsafe;
    use base64::Engine;
    use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
    use ed25519_dalek as ed25519;
    use prost::Message;
    use std::str::FromStr;
    use uuid::Uuid;

    use crate::handlers::test_utils::{self, gen_bytes};
    use crate::middleware::auth::RequestAuthTokenType;
    use crate::middleware::Limiter;
    use crate::services::api::RouteLimiters;

    #[actix_web::test]
    async fn test_lookup_user_public_key() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, _, _) = test_utils::create_user().await;

        let req = TestRequest::get()
            .uri(&format!("/api/user/public_key?email={}", user.email))
            .insert_header(("AccessToken", access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_public_key = UserPublicKey::decode(resp_body).unwrap();
        assert_eq!(
            user.public_key_id,
            <&UuidMessage as TryInto<Uuid>>::try_into(&resp_public_key.id).unwrap()
        );
        assert_eq!(user.public_key, resp_public_key.value);
    }

    #[actix_web::test]
    async fn test_create_user() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let user_number = SecureRng::next_u128();
        let public_key_id = Uuid::now_v7();

        let new_user = NewUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: gen_bytes(10),

            auth_string_hash_salt: gen_bytes(10),
            auth_string_hash_mem_cost_kib: 1024,
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

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        VerificationEmailSent::decode(resp_body).unwrap();

        let user = users
            .filter(user_fields::email.eq(&new_user.email))
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(user.email, new_user.email);
        assert_eq!(user.auth_string_hash_salt, new_user.auth_string_hash_salt);
        assert_eq!(
            user.auth_string_hash_mem_cost_kib,
            new_user.auth_string_hash_mem_cost_kib
        );
        assert_eq!(
            user.auth_string_hash_threads,
            new_user.auth_string_hash_threads
        );
        assert_eq!(
            user.auth_string_hash_iterations,
            new_user.auth_string_hash_iterations
        );
        assert_eq!(
            user.password_encryption_key_salt,
            new_user.password_encryption_key_salt
        );
        assert_eq!(
            user.password_encryption_key_mem_cost_kib,
            new_user.password_encryption_key_mem_cost_kib
        );
        assert_eq!(
            user.password_encryption_key_threads,
            new_user.password_encryption_key_threads
        );
        assert_eq!(
            user.password_encryption_key_iterations,
            new_user.password_encryption_key_iterations
        );
        assert_eq!(
            user.recovery_key_hash_salt_for_encryption,
            new_user.recovery_key_hash_salt_for_encryption
        );
        assert_eq!(
            user.recovery_key_hash_salt_for_recovery_auth,
            new_user.recovery_key_hash_salt_for_recovery_auth
        );
        assert_eq!(
            user.recovery_key_hash_mem_cost_kib,
            new_user.recovery_key_hash_mem_cost_kib
        );
        assert_eq!(
            user.recovery_key_hash_threads,
            new_user.recovery_key_hash_threads
        );
        assert_eq!(
            user.recovery_key_hash_iterations,
            new_user.recovery_key_hash_iterations
        );
        assert_eq!(
            user.encryption_key_encrypted_with_password,
            new_user.encryption_key_encrypted_with_password
        );
        assert_eq!(
            user.encryption_key_encrypted_with_recovery_key,
            new_user.encryption_key_encrypted_with_recovery_key
        );
        assert_eq!(user.public_key_id, public_key_id);
        assert_eq!(user.public_key, new_user.public_key);

        assert!(argon2_kdf::Hash::from_str(&user.auth_string_hash)
            .unwrap()
            .verify_with_secret(
                &new_user.auth_string,
                (&env::CONF.auth_string_hash_key).into()
            ));

        // Test password was hashed with correct params
        let hash_start_pos = user.auth_string_hash.rfind('$').unwrap() + 1;
        let hash_len: u32 = b64_nopad
            .decode(&user.auth_string_hash[hash_start_pos..])
            .unwrap()
            .len()
            .try_into()
            .unwrap();

        assert_eq!(hash_len, env::CONF.auth_string_hash_length);

        let salt_start_pos = user.auth_string_hash[..(hash_start_pos - 1)]
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

        assert_eq!(salt_len, env::CONF.auth_string_hash_salt_length);

        assert!(user.auth_string_hash.contains("argon2id"));
        assert!(user
            .auth_string_hash
            .contains(&format!("m={}", env::CONF.auth_string_hash_mem_cost_kib)));
        assert!(user
            .auth_string_hash
            .contains(&format!("t={}", env::CONF.auth_string_hash_iterations)));
        assert!(user
            .auth_string_hash
            .contains(&format!("p={}", env::CONF.auth_string_hash_threads)));

        let (keystore, keystore_version_nonce) = user_keystores
            .select((
                user_keystore_fields::encrypted_blob,
                user_keystore_fields::version_nonce,
            ))
            .find(user.id)
            .get_result::<(Vec<u8>, i64)>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(keystore, new_user.user_keystore_encrypted);
        assert_eq!(keystore_version_nonce, new_user.user_keystore_version_nonce);

        let (preferences, preferences_version_nonce) = user_preferences
            .select((
                user_preferences_fields::encrypted_blob,
                user_preferences_fields::version_nonce,
            ))
            .find(user.id)
            .get_result::<(Vec<u8>, i64)>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(preferences, new_user.preferences_encrypted);
        assert_eq!(
            preferences_version_nonce,
            new_user.preferences_version_nonce
        );

        assert!(
            dsl::select(dsl::exists(signin_nonces.find(&new_user.email)))
                .get_result::<bool>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
        );
    }

    #[actix_web::test]
    #[ignore]
    async fn test_create_user_fails_with_large_input() {
        let mut protobuf_config = ProtoBufConfig::default();
        protobuf_config.limit(env::CONF.protobuf_max_size);
        let route_limiters = RouteLimiters {
            create_user: Limiter::new(15, Duration::from_secs(1200), Duration::from_secs(3600)),
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

        let user_number = SecureRng::next_u128();

        let public_key_id = Uuid::now_v7();

        let new_user = NewUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: gen_bytes(10),

            auth_string_hash_salt: gen_bytes(10),
            auth_string_hash_mem_cost_kib: 1024,
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

        let mut temp = new_user.clone();
        temp.auth_string = gen_bytes(env::CONF.max_auth_string_length + 1);
        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let mut temp = new_user.clone();
        temp.auth_string_hash_salt = vec![0; env::CONF.max_encryption_key_size + 1];
        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let mut temp = new_user.clone();
        temp.password_encryption_key_salt = vec![0; env::CONF.max_encryption_key_size + 1];
        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let mut temp = new_user.clone();
        temp.recovery_key_hash_salt_for_encryption = vec![0; env::CONF.max_encryption_key_size + 1];
        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let mut temp = new_user.clone();
        temp.recovery_key_hash_salt_for_recovery_auth =
            vec![0; env::CONF.max_encryption_key_size + 1];
        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let mut temp = new_user.clone();
        temp.recovery_key_auth_hash = vec![0; env::CONF.max_encryption_key_size + 1];
        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let mut temp = new_user.clone();
        temp.encryption_key_encrypted_with_password =
            vec![0; env::CONF.max_encryption_key_size + 1];
        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let mut temp = new_user.clone();
        temp.encryption_key_encrypted_with_recovery_key =
            vec![0; env::CONF.max_encryption_key_size + 1];
        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let mut temp = new_user.clone();
        temp.public_key = vec![0; env::CONF.max_encryption_key_size + 1];
        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let mut temp = new_user.clone();
        temp.preferences_encrypted = vec![0; env::CONF.max_user_preferences_size + 1];
        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(temp.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let mut temp = new_user.clone();
        temp.user_keystore_encrypted = vec![0; env::CONF.max_keystore_size + 1];
        let req = TestRequest::post()
            .uri("/api/user")
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
    async fn test_verify_creation() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let user_number = SecureRng::next_u128();

        let public_key_id = Uuid::now_v7();
        let new_user = NewUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: vec![8; 10],

            auth_string_hash_salt: vec![8; 10],
            auth_string_hash_mem_cost_kib: 1024,
            auth_string_hash_threads: 1,
            auth_string_hash_iterations: 2,

            password_encryption_key_salt: vec![8; 10],
            password_encryption_key_mem_cost_kib: 1024,
            password_encryption_key_threads: 1,
            password_encryption_key_iterations: 1,

            recovery_key_hash_salt_for_encryption: vec![8; 16],
            recovery_key_hash_salt_for_recovery_auth: vec![8; 16],
            recovery_key_hash_mem_cost_kib: 1024,
            recovery_key_hash_threads: 1,
            recovery_key_hash_iterations: 1,

            recovery_key_auth_hash: vec![8; 32],

            encryption_key_encrypted_with_password: vec![8; 10],
            encryption_key_encrypted_with_recovery_key: vec![8; 10],

            public_key_id: public_key_id.into(),
            public_key: vec![8; 10],

            preferences_encrypted: vec![8; 10],
            preferences_version_nonce: SecureRng::next_i64(),
            user_keystore_encrypted: vec![8; 10],
            user_keystore_version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_user.encode_to_vec())
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
            expiration: (SystemTime::now() + env::CONF.access_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .expect("System time should be after Unix Epoch")
                .as_secs(),
            token_type: AuthTokenType::UserCreation,
        };

        let user_creation_token =
            AuthToken::sign_new(user_creation_token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::get()
            .uri(&format!(
                "/api/user/verify?UserCreationToken={}",
                &user_creation_token[..(user_creation_token.len() - 4)],
            ))
            .set_payload(new_user.encode_to_vec())
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
                "/api/user/verify?UserCreationToken={}",
                user_creation_token,
            ))
            .set_payload(new_user.encode_to_vec())
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
    async fn test_rotate_user_public_key() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, _, _) = test_utils::create_user().await;

        let new_key_id = Uuid::now_v7();
        let new_key = [8; 30];

        let old_key_update = NewUserPublicKey {
            id: (&new_key_id).into(),
            value: new_key.to_vec(),
            expected_previous_public_key_id: Uuid::now_v7().into(),
        };

        let req = TestRequest::put()
            .uri("/api/user/public_key")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(old_key_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();
        assert_eq!(resp_err.err_type, ErrorType::OutOfDate as i32);

        let user_after_req = users
            .find(user.id)
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(user_after_req.public_key_id, user.public_key_id);
        assert_eq!(user_after_req.public_key, user.public_key);

        let key_update = NewUserPublicKey {
            id: (&new_key_id).into(),
            value: new_key.to_vec(),
            expected_previous_public_key_id: (&user.public_key_id).into(),
        };

        let req = TestRequest::put()
            .uri("/api/user/public_key")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(key_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let user_after_req = users
            .find(user.id)
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_ne!(user_after_req.public_key_id, user.public_key_id);
        assert_ne!(user_after_req.public_key, user.public_key);
        assert_eq!(user_after_req.public_key_id, new_key_id);
        assert_eq!(user_after_req.public_key, new_key);
    }

    #[actix_web::test]
    #[ignore]
    async fn test_rotate_user_public_key_fails_with_large_input() {
        let mut protobuf_config = ProtoBufConfig::default();
        protobuf_config.limit(env::CONF.protobuf_max_size);
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(protobuf_config)
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, _, _) = test_utils::create_user().await;

        let key_update = NewUserPublicKey {
            id: (&Uuid::now_v7()).into(),
            value: vec![0; env::CONF.max_encryption_key_size + 1],
            expected_previous_public_key_id: (&user.public_key_id).into(),
        };

        let req = TestRequest::put()
            .uri("/api/user/public_key")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(key_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_web::test]
    async fn test_edit_preferences() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, preferences_version_nonce, _) = test_utils::create_user().await;

        let updated_prefs_blob: Vec<_> = (0..32).map(|_| SecureRng::next_u8()).collect();

        let updated_prefs = EncryptedBlobUpdate {
            encrypted_blob: updated_prefs_blob.clone(),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: preferences_version_nonce.wrapping_add(1),
        };

        let req = TestRequest::put()
            .uri("/api/user/preferences")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(updated_prefs.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_err.err_type, ErrorType::OutOfDate as i32);

        let (stored_prefs_blob, stored_prefs_version_nonce) = user_preferences
            .select((
                user_preferences_fields::encrypted_blob,
                user_preferences_fields::version_nonce,
            ))
            .find(user.id)
            .first::<(Vec<u8>, i64)>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_ne!(stored_prefs_blob, updated_prefs_blob);
        assert_ne!(stored_prefs_version_nonce, updated_prefs.version_nonce);

        let updated_prefs = EncryptedBlobUpdate {
            encrypted_blob: updated_prefs_blob,
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: preferences_version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/user/preferences")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(updated_prefs.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let (stored_prefs_blob, stored_prefs_version_nonce) = user_preferences
            .select((
                user_preferences_fields::encrypted_blob,
                user_preferences_fields::version_nonce,
            ))
            .find(user.id)
            .get_result::<(Vec<u8>, i64)>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(stored_prefs_blob, updated_prefs.encrypted_blob);
        assert_eq!(stored_prefs_version_nonce, updated_prefs.version_nonce);
    }

    #[actix_web::test]
    #[ignore]
    async fn test_edit_preferences_fails_with_large_input() {
        let mut protobuf_config = ProtoBufConfig::default();
        protobuf_config.limit(env::CONF.protobuf_max_size);
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(protobuf_config)
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, preferences_version_nonce, _) = test_utils::create_user().await;

        let updated_prefs = EncryptedBlobUpdate {
            encrypted_blob: vec![0; env::CONF.max_user_preferences_size + 1],
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: preferences_version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/user/preferences")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(updated_prefs.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_web::test]
    async fn test_edit_keystore() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, _, keystore_version_nonce) = test_utils::create_user().await;

        let updated_keystore_blob: Vec<_> = (0..32).map(|_| SecureRng::next_u8()).collect();

        let updated_keystore = EncryptedBlobUpdate {
            encrypted_blob: updated_keystore_blob.clone(),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: keystore_version_nonce.wrapping_add(1),
        };

        let req = TestRequest::put()
            .uri("/api/user/keystore")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(updated_keystore.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_err.err_type, ErrorType::OutOfDate as i32);

        let (stored_keystore_blob, stored_keystore_version_nonce) = user_keystores
            .select((
                user_keystore_fields::encrypted_blob,
                user_keystore_fields::version_nonce,
            ))
            .find(user.id)
            .first::<(Vec<u8>, i64)>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_ne!(stored_keystore_blob, updated_keystore_blob);
        assert_ne!(
            stored_keystore_version_nonce,
            updated_keystore.version_nonce
        );

        let updated_keystore = EncryptedBlobUpdate {
            encrypted_blob: updated_keystore_blob,
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: keystore_version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/user/keystore")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(updated_keystore.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let (stored_keystore_blob, stored_keystore_version_nonce) = user_keystores
            .select((
                user_keystore_fields::encrypted_blob,
                user_keystore_fields::version_nonce,
            ))
            .find(user.id)
            .get_result::<(Vec<u8>, i64)>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(stored_keystore_blob, updated_keystore.encrypted_blob);
        assert_eq!(
            stored_keystore_version_nonce,
            updated_keystore.version_nonce
        );
    }

    #[actix_web::test]
    #[ignore]
    async fn test_edit_keystore_fails_with_large_input() {
        let mut protobuf_config = ProtoBufConfig::default();
        protobuf_config.limit(env::CONF.protobuf_max_size);
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(protobuf_config)
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, keystore_version_nonce) = test_utils::create_user().await;

        let updated_keystore = EncryptedBlobUpdate {
            encrypted_blob: vec![0; env::CONF.max_keystore_size + 1],
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: keystore_version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/user/keystore")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(updated_keystore.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_web::test]
    async fn test_change_password() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, _, _) = test_utils::create_user().await;

        // Make sure an OTP is generated
        let req = TestRequest::get()
            .uri("/api/auth/otp")
            .insert_header(("AccessToken", access_token.as_str()))
            .to_request();
        test::call_service(&app, req).await;

        let otp = user_otps
            .select(user_otp_fields::otp)
            .find(&user.email)
            .get_result::<String>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let updated_auth_string: Vec<_> = gen_bytes(256);
        let updated_auth_string_hash_salt: Vec<_> = gen_bytes(16);
        let updated_password_encryption_key_salt: Vec<_> = gen_bytes(16);
        let updated_encrypted_encryption_key: Vec<_> = gen_bytes(48);

        let mut edit_password = AuthStringAndEncryptedPasswordUpdate {
            user_email: user.email.clone(),
            otp: String::from("ABCDEFGH"),

            new_auth_string: updated_auth_string.clone(),

            auth_string_hash_salt: updated_auth_string_hash_salt.clone(),

            auth_string_hash_mem_cost_kib: 11,
            auth_string_hash_threads: 13,
            auth_string_hash_iterations: 17,

            password_encryption_key_salt: updated_password_encryption_key_salt.clone(),

            password_encryption_key_mem_cost_kib: 13,
            password_encryption_key_threads: 17,
            password_encryption_key_iterations: 19,

            encrypted_encryption_key: updated_encrypted_encryption_key,
        };

        let req = TestRequest::put()
            .uri("/api/user/password")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(edit_password.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_err.err_type, ErrorType::IncorrectCredential as i32);

        let stored_user = users
            .find(user.id)
            .get_result::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert!(!argon2_kdf::Hash::from_str(&stored_user.auth_string_hash)
            .unwrap()
            .verify_with_secret(
                &edit_password.new_auth_string,
                (&env::CONF.auth_string_hash_key).into()
            ));

        assert_ne!(
            stored_user.auth_string_hash_salt,
            edit_password.auth_string_hash_salt
        );
        assert_ne!(
            stored_user.auth_string_hash_mem_cost_kib,
            edit_password.auth_string_hash_mem_cost_kib
        );
        assert_ne!(
            stored_user.auth_string_hash_threads,
            edit_password.auth_string_hash_threads
        );
        assert_ne!(
            stored_user.auth_string_hash_iterations,
            edit_password.auth_string_hash_iterations
        );

        assert_ne!(
            stored_user.password_encryption_key_salt,
            edit_password.password_encryption_key_salt
        );
        assert_ne!(
            stored_user.password_encryption_key_mem_cost_kib,
            edit_password.password_encryption_key_mem_cost_kib
        );
        assert_ne!(
            stored_user.password_encryption_key_threads,
            edit_password.password_encryption_key_threads
        );
        assert_ne!(
            stored_user.password_encryption_key_iterations,
            edit_password.password_encryption_key_iterations
        );

        assert_ne!(
            stored_user.encryption_key_encrypted_with_password,
            edit_password.encrypted_encryption_key
        );

        edit_password.otp = otp;

        let req = TestRequest::put()
            .uri("/api/user/password")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(edit_password.encode_to_vec())
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
                (&env::CONF.auth_string_hash_key).into()
            ));

        assert_eq!(
            stored_user.auth_string_hash_salt,
            edit_password.auth_string_hash_salt
        );
        assert_eq!(
            stored_user.auth_string_hash_mem_cost_kib,
            edit_password.auth_string_hash_mem_cost_kib
        );
        assert_eq!(
            stored_user.auth_string_hash_threads,
            edit_password.auth_string_hash_threads
        );
        assert_eq!(
            stored_user.auth_string_hash_iterations,
            edit_password.auth_string_hash_iterations
        );

        assert_eq!(
            stored_user.password_encryption_key_salt,
            edit_password.password_encryption_key_salt
        );
        assert_eq!(
            stored_user.password_encryption_key_mem_cost_kib,
            edit_password.password_encryption_key_mem_cost_kib
        );
        assert_eq!(
            stored_user.password_encryption_key_threads,
            edit_password.password_encryption_key_threads
        );
        assert_eq!(
            stored_user.password_encryption_key_iterations,
            edit_password.password_encryption_key_iterations
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

        assert_eq!(hash_len, env::CONF.auth_string_hash_length);

        let salt_start_pos = stored_user.auth_string_hash[..(hash_start_pos - 1)]
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

        assert_eq!(salt_len, env::CONF.auth_string_hash_salt_length);

        assert!(stored_user.auth_string_hash.contains("argon2id"));
        assert!(stored_user
            .auth_string_hash
            .contains(&format!("m={}", env::CONF.auth_string_hash_mem_cost_kib)));
        assert!(stored_user
            .auth_string_hash
            .contains(&format!("t={}", env::CONF.auth_string_hash_iterations)));
        assert!(stored_user
            .auth_string_hash
            .contains(&format!("p={}", env::CONF.auth_string_hash_threads)));
    }

    #[actix_web::test]
    #[ignore]
    async fn test_change_password_fails_with_large_input() {
        let mut protobuf_config = ProtoBufConfig::default();
        protobuf_config.limit(env::CONF.protobuf_max_size);
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(protobuf_config)
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, _, _) = test_utils::create_user().await;

        // Make sure an OTP is generated
        let req = TestRequest::get()
            .uri("/api/auth/otp")
            .insert_header(("AccessToken", access_token.as_str()))
            .to_request();
        test::call_service(&app, req).await;

        let otp = user_otps
            .select(user_otp_fields::otp)
            .find(&user.email)
            .get_result::<String>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let edit_password = AuthStringAndEncryptedPasswordUpdate {
            user_email: user.email.clone(),
            otp: otp.clone(),

            new_auth_string: vec![0; env::CONF.max_auth_string_length + 1],

            auth_string_hash_salt: gen_bytes(16),

            auth_string_hash_mem_cost_kib: 11,
            auth_string_hash_threads: 13,
            auth_string_hash_iterations: 17,

            password_encryption_key_salt: gen_bytes(16),

            password_encryption_key_mem_cost_kib: 13,
            password_encryption_key_threads: 17,
            password_encryption_key_iterations: 19,

            encrypted_encryption_key: gen_bytes(48),
        };

        let req = TestRequest::put()
            .uri("/api/user/password")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(edit_password.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let edit_password = AuthStringAndEncryptedPasswordUpdate {
            user_email: user.email.clone(),
            otp: otp.clone(),

            new_auth_string: gen_bytes(32),

            auth_string_hash_salt: vec![0; env::CONF.max_encryption_key_size + 1],

            auth_string_hash_mem_cost_kib: 11,
            auth_string_hash_threads: 13,
            auth_string_hash_iterations: 17,

            password_encryption_key_salt: gen_bytes(16),

            password_encryption_key_mem_cost_kib: 13,
            password_encryption_key_threads: 17,
            password_encryption_key_iterations: 19,

            encrypted_encryption_key: gen_bytes(48),
        };

        let req = TestRequest::put()
            .uri("/api/user/password")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(edit_password.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let edit_password = AuthStringAndEncryptedPasswordUpdate {
            user_email: user.email.clone(),
            otp: otp.clone(),

            new_auth_string: gen_bytes(32),

            auth_string_hash_salt: gen_bytes(16),

            auth_string_hash_mem_cost_kib: 11,
            auth_string_hash_threads: 13,
            auth_string_hash_iterations: 17,

            password_encryption_key_salt: vec![0; env::CONF.max_encryption_key_size + 1],

            password_encryption_key_mem_cost_kib: 13,
            password_encryption_key_threads: 17,
            password_encryption_key_iterations: 19,

            encrypted_encryption_key: gen_bytes(48),
        };

        let req = TestRequest::put()
            .uri("/api/user/password")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(edit_password.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let edit_password = AuthStringAndEncryptedPasswordUpdate {
            user_email: user.email.clone(),
            otp: otp.clone(),

            new_auth_string: gen_bytes(32),

            auth_string_hash_salt: gen_bytes(16),

            auth_string_hash_mem_cost_kib: 11,
            auth_string_hash_threads: 13,
            auth_string_hash_iterations: 17,

            password_encryption_key_salt: gen_bytes(16),

            password_encryption_key_mem_cost_kib: 13,
            password_encryption_key_threads: 17,
            password_encryption_key_iterations: 19,

            encrypted_encryption_key: vec![0; env::CONF.max_encryption_key_size + 1],
        };

        let req = TestRequest::put()
            .uri("/api/user/password")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(edit_password.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_web::test]
    async fn test_change_recovery_key() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, _, _) = test_utils::create_user().await;

        // Make sure an OTP is generated
        let req = TestRequest::get()
            .uri("/api/auth/otp")
            .insert_header(("AccessToken", access_token.as_str()))
            .to_request();
        test::call_service(&app, req).await;

        let otp = user_otps
            .select(user_otp_fields::otp)
            .find(&user.email)
            .get_result::<String>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let updated_recovery_key_hash_salt_for_encryption: Vec<_> = gen_bytes(16);
        let updated_recovery_key_hash_salt_for_recovery_auth: Vec<_> = gen_bytes(16);
        let updated_recovery_key_auth_hash: Vec<_> = gen_bytes(32);
        let updated_encrypted_encryption_key: Vec<_> = gen_bytes(48);

        let mut edit_recovery_key = RecoveryKeyUpdate {
            otp: String::from("ABCDEFGH"),

            recovery_key_hash_salt_for_encryption: updated_recovery_key_hash_salt_for_encryption
                .clone(),
            recovery_key_hash_salt_for_recovery_auth:
                updated_recovery_key_hash_salt_for_recovery_auth.clone(),

            recovery_key_hash_mem_cost_kib: 11,
            recovery_key_hash_threads: 13,
            recovery_key_hash_iterations: 17,

            recovery_key_auth_hash: updated_recovery_key_auth_hash,

            encrypted_encryption_key: updated_encrypted_encryption_key,
        };

        let req = TestRequest::put()
            .uri("/api/user/recovery_key")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(edit_recovery_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_err.err_type, ErrorType::IncorrectCredential as i32);

        edit_recovery_key.otp = otp;

        let req = TestRequest::put()
            .uri("/api/user/recovery_key")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(edit_recovery_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_err.err_type, ErrorType::TokenMissing as i32);

        let stored_user = users
            .find(user.id)
            .get_result::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_ne!(
            stored_user.recovery_key_hash_salt_for_encryption,
            edit_recovery_key.recovery_key_hash_salt_for_encryption
        );
        assert_ne!(
            stored_user.recovery_key_hash_salt_for_recovery_auth,
            edit_recovery_key.recovery_key_hash_salt_for_recovery_auth
        );
        assert_ne!(
            stored_user.recovery_key_hash_mem_cost_kib,
            edit_recovery_key.recovery_key_hash_mem_cost_kib
        );
        assert_ne!(
            stored_user.recovery_key_hash_threads,
            edit_recovery_key.recovery_key_hash_threads
        );
        assert_ne!(
            stored_user.recovery_key_hash_iterations,
            edit_recovery_key.recovery_key_hash_iterations
        );
        assert_ne!(
            stored_user.encryption_key_encrypted_with_recovery_key,
            edit_recovery_key.encrypted_encryption_key
        );

        let req = TestRequest::put()
            .uri("/api/user/recovery_key")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(edit_recovery_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let stored_user = users
            .find(user.id)
            .get_result::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(
            stored_user.recovery_key_hash_salt_for_encryption,
            edit_recovery_key.recovery_key_hash_salt_for_encryption
        );
        assert_eq!(
            stored_user.recovery_key_hash_salt_for_recovery_auth,
            edit_recovery_key.recovery_key_hash_salt_for_recovery_auth
        );
        assert_eq!(
            stored_user.recovery_key_hash_mem_cost_kib,
            edit_recovery_key.recovery_key_hash_mem_cost_kib
        );
        assert_eq!(
            stored_user.recovery_key_hash_threads,
            edit_recovery_key.recovery_key_hash_threads
        );
        assert_eq!(
            stored_user.recovery_key_hash_iterations,
            edit_recovery_key.recovery_key_hash_iterations
        );
        assert_eq!(
            stored_user.encryption_key_encrypted_with_recovery_key,
            edit_recovery_key.encrypted_encryption_key
        );
    }

    #[actix_web::test]
    #[ignore]
    async fn test_change_recovery_key_fails_with_large_input() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, _, _) = test_utils::create_user().await;

        // Make sure an OTP is generated
        let req = TestRequest::get()
            .uri("/api/auth/otp")
            .insert_header(("AccessToken", access_token.as_str()))
            .to_request();
        test::call_service(&app, req).await;

        let otp = user_otps
            .select(user_otp_fields::otp)
            .find(&user.email)
            .get_result::<String>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let edit_recovery_key = RecoveryKeyUpdate {
            otp: otp.clone(),

            recovery_key_hash_salt_for_encryption: vec![0; env::CONF.max_encryption_key_size + 1],
            recovery_key_hash_salt_for_recovery_auth: gen_bytes(16),

            recovery_key_hash_mem_cost_kib: 11,
            recovery_key_hash_threads: 13,
            recovery_key_hash_iterations: 17,

            recovery_key_auth_hash: gen_bytes(32),

            encrypted_encryption_key: gen_bytes(48),
        };

        let req = TestRequest::put()
            .uri("/api/user/recovery_key")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(edit_recovery_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let edit_recovery_key = RecoveryKeyUpdate {
            otp: otp.clone(),

            recovery_key_hash_salt_for_encryption: gen_bytes(16),
            recovery_key_hash_salt_for_recovery_auth: vec![
                0;
                env::CONF.max_encryption_key_size + 1
            ],

            recovery_key_hash_mem_cost_kib: 11,
            recovery_key_hash_threads: 13,
            recovery_key_hash_iterations: 17,

            recovery_key_auth_hash: gen_bytes(32),

            encrypted_encryption_key: gen_bytes(48),
        };

        let req = TestRequest::put()
            .uri("/api/user/recovery_key")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(edit_recovery_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let edit_recovery_key = RecoveryKeyUpdate {
            otp: otp.clone(),

            recovery_key_hash_salt_for_encryption: gen_bytes(16),
            recovery_key_hash_salt_for_recovery_auth: gen_bytes(16),

            recovery_key_hash_mem_cost_kib: 11,
            recovery_key_hash_threads: 13,
            recovery_key_hash_iterations: 17,

            recovery_key_auth_hash: vec![0; env::CONF.max_encryption_key_size + 1],

            encrypted_encryption_key: gen_bytes(48),
        };

        let req = TestRequest::put()
            .uri("/api/user/recovery_key")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(edit_recovery_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let edit_recovery_key = RecoveryKeyUpdate {
            otp: otp.clone(),

            recovery_key_hash_salt_for_encryption: gen_bytes(16),
            recovery_key_hash_salt_for_recovery_auth: gen_bytes(16),

            recovery_key_hash_mem_cost_kib: 11,
            recovery_key_hash_threads: 13,
            recovery_key_hash_iterations: 17,

            recovery_key_auth_hash: gen_bytes(32),

            encrypted_encryption_key: vec![0; env::CONF.max_encryption_key_size + 1],
        };

        let req = TestRequest::put()
            .uri("/api/user/recovery_key")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(edit_recovery_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_web::test]
    #[ignore]
    async fn test_init_delete_fails_with_large_input() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let tokens = vec![String::from("test"); env::CONF.max_containers + 1];

        let container_access_tokens = ContainerAccessTokenList { tokens };

        let req = TestRequest::delete()
            .uri("/api/user")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_access_tokens.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_web::test]
    async fn test_delete_user_no_containers() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        // Test init_delete with no container tokens
        let (user, access_token, _, _) = test_utils::create_user().await;

        let container_access_tokens = ContainerAccessTokenList { tokens: Vec::new() };

        let req = TestRequest::delete()
            .uri("/api/user")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_access_tokens.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = VerificationEmailSent::decode(resp_body).unwrap();
        assert!(resp_body.email_sent);

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);

        let deletion_request_container_key_count = user_deletion_request_container_keys
            .filter(user_deletion_request_container_key_fields::user_id.eq(user.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_container_key_count, 0);

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
            expiration: (SystemTime::now() + env::CONF.user_deletion_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .expect("System time should be after Unix Epoch")
                .as_secs(),
            token_type: AuthTokenType::UserDeletion,
        };

        let user_deletion_token =
            AuthToken::sign_new(user_deletion_token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::get()
            .uri(&format!(
                "/api/user/deletion/verify?{}={}",
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

        let deletion_request_container_key_count = user_deletion_request_container_keys
            .filter(user_deletion_request_container_key_fields::user_id.eq(user.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_container_key_count, 0);

        assert_eq!(
            users
                .filter(user_fields::id.eq(user.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        let user_dao = db::user::Dao::new(&env::testing::DB_THREAD_POOL);
        user_dao.delete_user(&deletion_requests[0]).unwrap();

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);

        let deletion_request_container_key_count = user_deletion_request_container_keys
            .filter(user_deletion_request_container_key_fields::user_id.eq(user.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_container_key_count, 0);

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
    async fn test_delete_user_with_containers() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, _, _) = test_utils::create_user().await;

        let (container1, container1_token) = test_utils::create_container(&access_token).await;
        let (container2, container2_token) = test_utils::create_container(&access_token).await;

        let new_entry_and_category = EntryAndCategory {
            entry_encrypted_blob: gen_bytes(30),
            entry_version_nonce: SecureRng::next_i64(),
            category_encrypted_blob: gen_bytes(14),
            category_version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/container/entry_and_category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container1_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry_and_category.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let new_entry_and_category_ids = EntryIdAndCategoryId::decode(resp_body).unwrap();

        let new_entry_id: Uuid = new_entry_and_category_ids.entry_id.try_into().unwrap();
        let new_category_id: Uuid = new_entry_and_category_ids.category_id.try_into().unwrap();

        let decoded = b64_urlsafe.decode(&container1_token).unwrap();
        let json_len = decoded.len() - ed25519::SIGNATURE_LENGTH;
        let container1_access_key_id =
            serde_json::from_slice::<ContainerAccessTokenClaims>(&decoded[..json_len])
                .unwrap()
                .key_id;

        let decoded = b64_urlsafe.decode(&container2_token).unwrap();
        let json_len = decoded.len() - ed25519::SIGNATURE_LENGTH;
        let container2_access_key_id =
            serde_json::from_slice::<ContainerAccessTokenClaims>(&decoded[..json_len])
                .unwrap()
                .key_id;

        let container_access_tokens = ContainerAccessTokenList {
            tokens: vec![container1_token, container2_token],
        };

        let req = TestRequest::delete()
            .uri("/api/user")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_access_tokens.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = VerificationEmailSent::decode(resp_body).unwrap();
        assert!(resp_body.email_sent);

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);

        let deletion_request_container_key_count = user_deletion_request_container_keys
            .filter(user_deletion_request_container_key_fields::user_id.eq(user.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_container_key_count, 2);

        assert_eq!(
            users
                .filter(user_fields::id.eq(user.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container1_access_key_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container2_access_key_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container1.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            entries
                .filter(entry_fields::id.eq(new_entry_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            categories
                .filter(category_fields::id.eq(new_category_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container2.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        let user_deletion_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: (SystemTime::now() + env::CONF.user_deletion_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .expect("System time should be after Unix Epoch")
                .as_secs(),
            token_type: AuthTokenType::UserDeletion,
        };

        let user_deletion_token =
            AuthToken::sign_new(user_deletion_token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::get()
            .uri(&format!(
                "/api/user/deletion/verify?{}={}",
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

        let deletion_request_container_key_count = user_deletion_request_container_keys
            .filter(user_deletion_request_container_key_fields::user_id.eq(user.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_container_key_count, 2);

        assert_eq!(
            users
                .filter(user_fields::id.eq(user.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container1_access_key_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container2_access_key_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container1.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            entries
                .filter(entry_fields::id.eq(new_entry_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            categories
                .filter(category_fields::id.eq(new_category_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container2.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        let user_dao = db::user::Dao::new(&env::testing::DB_THREAD_POOL);
        user_dao.delete_user(&deletion_requests[0]).unwrap();

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);

        let deletion_request_container_key_count = user_deletion_request_container_keys
            .filter(user_deletion_request_container_key_fields::user_id.eq(user.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_container_key_count, 0);

        assert_eq!(
            users
                .filter(user_fields::id.eq(user.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container1_access_key_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container2_access_key_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container1.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );

        assert_eq!(
            entries
                .filter(entry_fields::id.eq(new_entry_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );

        assert_eq!(
            categories
                .filter(category_fields::id.eq(new_category_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container2.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );
    }

    #[actix_web::test]
    async fn test_delete_user_fails_with_bad_token() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        // Test init_delete with no container tokens
        let (user, access_token, _, _) = test_utils::create_user().await;

        let (container1, container1_token) = test_utils::create_container(&access_token).await;
        let (container2, container2_token) = test_utils::create_container(&access_token).await;

        let decoded = b64_urlsafe.decode(&container1_token).unwrap();
        let json_len = decoded.len() - ed25519::SIGNATURE_LENGTH;
        let container1_access_key_id =
            serde_json::from_slice::<ContainerAccessTokenClaims>(&decoded[..json_len])
                .unwrap()
                .key_id;

        let decoded = b64_urlsafe.decode(&container2_token).unwrap();
        let json_len = decoded.len() - ed25519::SIGNATURE_LENGTH;
        let container2_access_key_id =
            serde_json::from_slice::<ContainerAccessTokenClaims>(&decoded[..json_len])
                .unwrap()
                .key_id;

        let mut bad_token = b64_urlsafe.decode(&container2_token).unwrap();

        // Make the signature invalid
        let last_char = bad_token.pop().unwrap();
        if last_char == b'a' {
            bad_token.push(b'b');
        } else {
            bad_token.push(b'a');
        }

        let bad_token = b64_urlsafe.encode(bad_token);

        let container_access_tokens = ContainerAccessTokenList {
            tokens: vec![container1_token.clone(), container2_token],
        };

        let container_access_tokens_incorrect = ContainerAccessTokenList {
            tokens: vec![container1_token, bad_token],
        };

        let req = TestRequest::delete()
            .uri("/api/user")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_access_tokens_incorrect.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = TestRequest::delete()
            .uri("/api/user")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_access_tokens.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = VerificationEmailSent::decode(resp_body).unwrap();
        assert!(resp_body.email_sent);

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);

        let deletion_request_container_key_count = user_deletion_request_container_keys
            .filter(user_deletion_request_container_key_fields::user_id.eq(user.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_container_key_count, 2);

        assert_eq!(
            users
                .filter(user_fields::id.eq(user.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container1_access_key_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container2_access_key_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container1.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container2.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        let user_deletion_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: (SystemTime::now() + env::CONF.user_deletion_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .expect("System time should be after Unix Epoch")
                .as_secs(),
            token_type: AuthTokenType::UserDeletion,
        };

        let user_deletion_token =
            AuthToken::sign_new(user_deletion_token_claims, &env::CONF.token_signing_key);

        let broken_user_deletion_token = &user_deletion_token[..user_deletion_token.len() - 1];

        let req = TestRequest::get()
            .uri(&format!(
                "/api/user/deletion/verify?{}={}",
                UserDeletion::token_name(),
                broken_user_deletion_token,
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);

        let deletion_request_container_key_count = user_deletion_request_container_keys
            .filter(user_deletion_request_container_key_fields::user_id.eq(user.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_container_key_count, 2);

        assert_eq!(
            users
                .filter(user_fields::id.eq(user.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container1_access_key_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container2_access_key_id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container1.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container2.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );
    }

    #[actix_web::test]
    async fn test_delete_user_succeeds_with_shared_containers() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        // Test init_delete with no container tokens
        let (user1, user1_access_token, _, _) = test_utils::create_user().await;
        let (user2, user2_access_token, _, _) = test_utils::create_user().await;

        test_utils::gen_new_user_rsa_key(user1.id);
        let user2_rsa_key = test_utils::gen_new_user_rsa_key(user2.id);

        let (container1, container1_token_user1) = test_utils::create_container(&user1_access_token).await;
        let (container2, container2_token_user1) = test_utils::create_container(&user1_access_token).await;

        let decoded = b64_urlsafe.decode(&container1_token_user1).unwrap();
        let json_len = decoded.len() - ed25519::SIGNATURE_LENGTH;
        let container1_access_key_id_user1 =
            serde_json::from_slice::<ContainerAccessTokenClaims>(&decoded[..json_len])
                .unwrap()
                .key_id;

        let decoded = b64_urlsafe.decode(&container2_token_user1).unwrap();
        let json_len = decoded.len() - ed25519::SIGNATURE_LENGTH;
        let container2_access_key_id_user1 =
            serde_json::from_slice::<ContainerAccessTokenClaims>(&decoded[..json_len])
                .unwrap()
                .key_id;

        let container2_token_user2 = test_utils::share_container(
            container2.id,
            &user2.email,
            &user2_rsa_key.private_key_to_der().unwrap(),
            true,
            &container2_token_user1,
            &user1_access_token,
            user2.public_key_id,
            user2.public_key_id,
        )
        .await;

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container2_token_user2.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", user2_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let container_access_tokens = ContainerAccessTokenList {
            tokens: vec![container1_token_user1, container2_token_user1],
        };

        let req = TestRequest::delete()
            .uri("/api/user")
            .insert_header(("AccessToken", user1_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_access_tokens.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = VerificationEmailSent::decode(resp_body).unwrap();
        assert!(resp_body.email_sent);

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user1.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);

        let deletion_request_container_key_count = user_deletion_request_container_keys
            .filter(user_deletion_request_container_key_fields::user_id.eq(user1.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_container_key_count, 2);

        assert_eq!(
            users
                .filter(user_fields::id.eq(user1.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container1_access_key_id_user1))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container2_access_key_id_user1))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container1.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container2.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container2_token_user2.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", user2_access_token.as_str()))
            .insert_header(("AccessToken", user2_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let user_deletion_token_claims = NewAuthTokenClaims {
            user_id: user1.id,
            user_email: &user1.email,
            expiration: (SystemTime::now() + env::CONF.user_deletion_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .expect("System time should be after Unix Epoch")
                .as_secs(),
            token_type: AuthTokenType::UserDeletion,
        };

        let user_deletion_token =
            AuthToken::sign_new(user_deletion_token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::get()
            .uri(&format!(
                "/api/user/deletion/verify?{}={}",
                UserDeletion::token_name(),
                user_deletion_token,
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user1.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 1);

        let deletion_request_container_key_count = user_deletion_request_container_keys
            .filter(user_deletion_request_container_key_fields::user_id.eq(user1.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_container_key_count, 2);

        assert_eq!(
            users
                .filter(user_fields::id.eq(user1.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container1_access_key_id_user1))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container2_access_key_id_user1))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container1.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container2.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::container_id.eq(container1.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::container_id.eq(container2.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            2,
        );

        let user_dao = db::user::Dao::new(&env::testing::DB_THREAD_POOL);
        user_dao.delete_user(&deletion_requests[0]).unwrap();

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user1.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);

        let deletion_request_container_key_count = user_deletion_request_container_keys
            .filter(user_deletion_request_container_key_fields::user_id.eq(user1.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_request_container_key_count, 0);

        assert_eq!(
            users
                .filter(user_fields::id.eq(user1.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container1_access_key_id_user1))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::key_id.eq(container2_access_key_id_user1))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container1.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container2.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::container_id.eq(container1.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::container_id.eq(container2.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1,
        );

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container2_token_user2.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", user2_access_token.as_str()))
            .insert_header(("AccessToken", user2_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        // Delete user 2
        let container_access_tokens = ContainerAccessTokenList {
            tokens: vec![container2_token_user2],
        };

        let req = TestRequest::delete()
            .uri("/api/user")
            .insert_header(("AccessToken", user2_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_access_tokens.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let user_deletion_token_claims = NewAuthTokenClaims {
            user_id: user2.id,
            user_email: &user2.email,
            expiration: (SystemTime::now() + env::CONF.user_deletion_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .expect("System time should be after Unix Epoch")
                .as_secs(),
            token_type: AuthTokenType::UserDeletion,
        };

        let user_deletion_token =
            AuthToken::sign_new(user_deletion_token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::get()
            .uri(&format!(
                "/api/user/deletion/verify?{}={}",
                UserDeletion::token_name(),
                user_deletion_token,
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user2.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 1);

        let user_dao = db::user::Dao::new(&env::testing::DB_THREAD_POOL);
        user_dao.delete_user(&deletion_requests[0]).unwrap();

        assert_eq!(
            users
                .filter(user_fields::id.eq(user2.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );

        assert_eq!(
            containers
                .filter(container_fields::id.eq(container2.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );

        assert_eq!(
            container_access_keys
                .filter(container_access_key_fields::container_id.eq(container2.id))
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0,
        );
    }

    #[actix_web::test]
    async fn test_check_user_is_listed_for_deletion() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        // Test init_delete with no container tokens
        let (user, access_token, _, _) = test_utils::create_user().await;

        let req = TestRequest::get()
            .uri("/api/user/deletion")
            .insert_header(("AccessToken", access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = IsUserListedForDeletion::decode(resp_body).unwrap();
        assert!(!resp_body.value);

        let container_access_tokens = ContainerAccessTokenList { tokens: Vec::new() };

        let req = TestRequest::delete()
            .uri("/api/user")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_access_tokens.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);

        let req = TestRequest::get()
            .uri("/api/user/deletion")
            .insert_header(("AccessToken", access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = IsUserListedForDeletion::decode(resp_body).unwrap();
        assert!(!resp_body.value);

        let user_deletion_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: (SystemTime::now() + env::CONF.user_deletion_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .expect("System time should be after Unix Epoch")
                .as_secs(),
            token_type: AuthTokenType::UserDeletion,
        };

        let user_deletion_token =
            AuthToken::sign_new(user_deletion_token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::get()
            .uri(&format!(
                "/api/user/deletion/verify?{}={}",
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

        let req = TestRequest::get()
            .uri("/api/user/deletion")
            .insert_header(("AccessToken", access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = IsUserListedForDeletion::decode(resp_body).unwrap();
        assert!(resp_body.value);

        let req = TestRequest::delete()
            .uri("/api/user/deletion")
            .insert_header(("AccessToken", access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);

        let req = TestRequest::get()
            .uri("/api/user/deletion")
            .insert_header(("AccessToken", access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = IsUserListedForDeletion::decode(resp_body).unwrap();
        assert!(!resp_body.value);
    }

    #[actix_web::test]
    async fn test_cancel_user_deletion() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        // Test init_delete with no container tokens
        let (user, access_token, _, _) = test_utils::create_user().await;

        let req = TestRequest::get()
            .uri("/api/user/deletion")
            .insert_header(("AccessToken", access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = IsUserListedForDeletion::decode(resp_body).unwrap();
        assert!(!resp_body.value);

        let container_access_tokens = ContainerAccessTokenList { tokens: Vec::new() };

        let req = TestRequest::delete()
            .uri("/api/user")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_access_tokens.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);

        let user_deletion_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: (SystemTime::now() + env::CONF.user_deletion_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .expect("System time should be after Unix Epoch")
                .as_secs(),
            token_type: AuthTokenType::UserDeletion,
        };

        let user_deletion_token =
            AuthToken::sign_new(user_deletion_token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::get()
            .uri(&format!(
                "/api/user/deletion/verify?{}={}",
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

        let req = TestRequest::delete()
            .uri("/api/user/deletion")
            .insert_header(("AccessToken", access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let deletion_requests = user_deletion_requests
            .filter(user_deletion_request_fields::user_id.eq(user.id))
            .get_results::<UserDeletionRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(deletion_requests.len(), 0);
    }

    #[actix_web::test]
    async fn test_change_email_success() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, _, _) = test_utils::create_user().await;
        let new_email = format!("new_email{}@test.com", SecureRng::next_u128());

        // Hash a known auth string and update the user's auth string hash in the database
        let known_auth_string = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let auth_string_hash = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.auth_string_hash_salt_length)
            .hash_length(env::CONF.auth_string_hash_length)
            .iterations(env::CONF.auth_string_hash_iterations)
            .memory_cost_kib(env::CONF.auth_string_hash_mem_cost_kib)
            .threads(env::CONF.auth_string_hash_threads)
            .secret((&env::CONF.auth_string_hash_key).into())
            .hash(&known_auth_string)
            .unwrap()
            .to_string();

        dsl::update(users.find(user.id))
            .set(user_fields::auth_string_hash.eq(auth_string_hash))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let email_change_request = EmailChangeRequest {
            new_email: new_email.clone(),
            auth_string: known_auth_string,
        };

        let req = TestRequest::put()
            .uri("/api/user/email")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(email_change_request.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        // Verify the email was actually changed in the database
        let updated_user = users
            .find(user.id)
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(updated_user.email, new_email);
        assert_ne!(updated_user.email, user.email);
    }

    #[actix_web::test]
    async fn test_change_email_fails_with_incorrect_auth_string() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, _, _) = test_utils::create_user().await;
        let new_email = format!("new_email{}@test.com", SecureRng::next_u128());

        // Hash a known auth string and update the user's auth string hash in the database
        let known_auth_string = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let auth_string_hash = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.auth_string_hash_salt_length)
            .hash_length(env::CONF.auth_string_hash_length)
            .iterations(env::CONF.auth_string_hash_iterations)
            .memory_cost_kib(env::CONF.auth_string_hash_mem_cost_kib)
            .threads(env::CONF.auth_string_hash_threads)
            .secret((&env::CONF.auth_string_hash_key).into())
            .hash(&known_auth_string)
            .unwrap()
            .to_string();

        dsl::update(users.find(user.id))
            .set(user_fields::auth_string_hash.eq(auth_string_hash))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let email_change_request = EmailChangeRequest {
            new_email: new_email.clone(),
            auth_string: gen_bytes(10), // Incorrect auth string
        };

        let req = TestRequest::put()
            .uri("/api/user/email")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(email_change_request.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();
        assert_eq!(resp_err.err_type, ErrorType::IncorrectCredential as i32);

        // Verify the email was not changed
        let updated_user = users
            .find(user.id)
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(updated_user.email, user.email);
        assert_ne!(updated_user.email, new_email);
    }

    #[actix_web::test]
    async fn test_change_email_fails_with_existing_email() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user1, access_token1, _, _) = test_utils::create_user().await;
        let (user2, _, _, _) = test_utils::create_user().await;

        // Hash a known auth string and update user1's auth string hash in the database
        let known_auth_string = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let auth_string_hash = argon2_kdf::Hasher::default()
            .algorithm(argon2_kdf::Algorithm::Argon2id)
            .salt_length(env::CONF.auth_string_hash_salt_length)
            .hash_length(env::CONF.auth_string_hash_length)
            .iterations(env::CONF.auth_string_hash_iterations)
            .memory_cost_kib(env::CONF.auth_string_hash_mem_cost_kib)
            .threads(env::CONF.auth_string_hash_threads)
            .secret((&env::CONF.auth_string_hash_key).into())
            .hash(&known_auth_string)
            .unwrap()
            .to_string();

        dsl::update(users.find(user1.id))
            .set(user_fields::auth_string_hash.eq(auth_string_hash))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let email_change_request = EmailChangeRequest {
            new_email: user2.email.clone(),
            auth_string: known_auth_string,
        };

        let req = TestRequest::put()
            .uri("/api/user/email")
            .insert_header(("AccessToken", access_token1.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(email_change_request.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();
        assert_eq!(resp_err.err_type, ErrorType::ConflictWithExisting as i32);

        // Verify the email was not changed
        let updated_user = users
            .find(user1.id)
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(updated_user.email, user1.email);
        assert_ne!(updated_user.email, user2.email);
    }

    #[actix_web::test]
    async fn test_change_email_fails_with_invalid_email_format() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, access_token, _, _) = test_utils::create_user().await;

        let email_change_request = EmailChangeRequest {
            new_email: "invalid-email-format".to_string(),
            auth_string: gen_bytes(10),
        };

        let req = TestRequest::put()
            .uri("/api/user/email")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(email_change_request.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();
        assert_eq!(resp_err.err_type, ErrorType::IncorrectlyFormed as i32);

        // Verify the email was not changed
        let updated_user = users
            .find(user.id)
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(updated_user.email, user.email);
    }

    #[actix_web::test]
    async fn test_change_email_fails_without_access_token() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, _, _, _) = test_utils::create_user().await;
        let new_email = format!("new_email{}@test.com", SecureRng::next_u128());

        let email_change_request = EmailChangeRequest {
            new_email: new_email.clone(),
            auth_string: gen_bytes(10),
        };

        let req = TestRequest::put()
            .uri("/api/user/email")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(email_change_request.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Verify the email was not changed
        let updated_user = users
            .find(user.id)
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(updated_user.email, user.email);
        assert_ne!(updated_user.email, new_email);
    }

    #[actix_web::test]
    async fn test_change_email_fails_with_expired_access_token() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (user, _, _, _) = test_utils::create_user().await;
        let new_email = format!("new_email{}@test.com", SecureRng::next_u128());

        // Create an expired access token
        let expired_access_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: (SystemTime::now() - Duration::from_secs(3600)) // 1 hour ago
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            token_type: AuthTokenType::Access,
        };

        let expired_access_token =
            AuthToken::sign_new(expired_access_token_claims, &env::CONF.token_signing_key);

        let email_change_request = EmailChangeRequest {
            new_email: new_email.clone(),
            auth_string: gen_bytes(10),
        };

        let req = TestRequest::put()
            .uri("/api/user/email")
            .insert_header(("AccessToken", expired_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(email_change_request.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Verify the email was not changed
        let updated_user = users
            .find(user.id)
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(updated_user.email, user.email);
        assert_ne!(updated_user.email, new_email);
    }
}
