use budgetapp_utils::db::{DaoError, DbThreadPool};
use budgetapp_utils::request_io::{
    InputEditUserKeystore, InputEditUserPrefs, InputNewAuthStringAndEncryptedPassword, InputUser,
    OutputIsUserListedForDeletion, OutputVerificationEmailSent,
};
use budgetapp_utils::token::auth_token::{AuthToken, AuthTokenType};
use budgetapp_utils::token::{Token, TokenError};
use budgetapp_utils::validators::{self, Validity};
use budgetapp_utils::{argon2_hasher, db};

use actix_web::{web, HttpResponse};
use std::time::{Duration, SystemTime};

use crate::env;
use crate::handlers::error::ServerError;
use crate::middleware::app_version::AppVersion;
use crate::middleware::auth::{Access, UnverifiedToken, UserCreation, UserDeletion, VerifiedToken};
use crate::middleware::{FromHeader, FromQuery};

pub async fn create(
    db_thread_pool: web::Data<DbThreadPool>,
    app_version: AppVersion,
    user_data: web::Json<InputUser>,
) -> Result<HttpResponse, ServerError> {
    if let Validity::Invalid(msg) = validators::validate_email_address(&user_data.email) {
        return Err(ServerError::InvalidFormat(Some(msg)));
    }

    let email = user_data.email.clone();

    let user_id = match web::block(move || {
        let auth_string_hash = argon2_hasher::hash_auth_string(
            &user_data.auth_string,
            &argon2_hasher::HashParams {
                salt_len: env::CONF.hashing.salt_length_bytes,
                hash_len: env::CONF.hashing.hash_length,
                hash_iterations: env::CONF.hashing.hash_iterations,
                hash_mem_size_kib: env::CONF.hashing.hash_mem_size_kib,
                hash_lanes: env::CONF.hashing.hash_lanes,
            },
            &env::CONF.keys.hashing_key,
        );

        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.create_user(user_data.0, &app_version.0, &auth_string_hash)
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            )) => {
                return Err(ServerError::AlreadyExists(Some(String::from(
                    "A user with the given email address already exists",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::InternalError(Some(String::from(
                    "Failed to create user",
                ))));
            }
        },
    };

    let mut user_creation_token = AuthToken::new(
        user_id,
        &email,
        SystemTime::now() + env::CONF.lifetimes.user_creation_token_lifetime,
        AuthTokenType::UserCreation,
    );

    user_creation_token.encrypt(&env::CONF.keys.token_encryption_cipher);
    let user_creation_token =
        user_creation_token.encode_and_sign(&env::CONF.keys.token_signing_key);

    // TODO: Don't print user creation token; email it!
    println!("\n\nUser Creation Token: {user_creation_token}\n\n");

    Ok(HttpResponse::Created().json(OutputVerificationEmailSent {
        email_sent: true,
        email_token_lifetime_hours: env::CONF.lifetimes.user_creation_token_lifetime.as_secs()
            / 3600,
    }))
}

pub async fn verify_creation(
    db_thread_pool: web::Data<DbThreadPool>,
    user_creation_token: VerifiedToken<UserCreation, FromQuery>,
) -> Result<HttpResponse, ServerError> {
    let claims = match user_creation_token.0 {
        Ok(c) => c,
        Err(TokenError::TokenExpired) => {
            return Ok(HttpResponse::BadRequest().content_type("text/html").body(
                "<!DOCTYPE html> \
                 <html> \
                 <head> \
                 <title>Entries App User Verification</title> \
                 </head> \
                 <body> \
                 <h1>This link has expired. You will need to recreate your account to obtain a new link.</h1> \
                 \
                 <script> \
                 const urlQueries = new URLSearchParams(window.location.search); \
                 const token = urlQueries.get('UserCreationToken'); \
                 \
                 if (token !== null) { \
                 const decoded_token = atob(token); \
                 const claims = JSON.parse(decoded_token); \
                 \
                 if (claims['exp'] !== null) { \
                 const hourAfterExpiration = claims['exp'] + 3600; \
                 const accountAvailableForRecreate = new Date(hourAfterExpiration * 1000); \
                 const now = new Date(); \
                 \
                 if (accountAvailableForRecreate > now) { \
                 let recreateMessage = document.createElement('h3'); \
                 \
                 const millisUntilCanRecreate = Math.abs(now - accountAvailableForRecreate); \
                 const minsUntilCanRecreate = Math.ceil((millisUntilCanRecreate / 1000) / 60); \
                 \
                 const timeString = minsUntilCanRecreate > 1 \
                 ? minsUntilCanRecreate + ' minutes.' \
                 : '1 minute.' \
                 \
                 recreateMessage.innerHTML = 'You can recreate your account in ' + timeString; \
                 \
                 document.body.appendChild(recreateMessage); \
                 } \
                 } \
                 } \
                 </script> \
                 </body> \
                 </html>"
            ));
        }
        Err(TokenError::TokenMissing) => {
            return Ok(HttpResponse::BadRequest().content_type("text/html").body(
                "<!DOCTYPE html> \
                 <html> \
                 <head> \
                 <title>Entries App User Verification</title> \
                 </head> \
                 <body> \
                 <h1>This link is invalid because it is missing a token.</h1> \
                 </body> \
                 </html>",
            ));
        }
        Err(TokenError::TokenExpired) | Err(TokenError::WrongTokenType) => {
            return Ok(HttpResponse::BadRequest().content_type("text/html").body(
                "<!DOCTYPE html> \
                 <html> \
                 <head> \
                 <title>Entries App User Verification</title> \
                 </head> \
                 <body> \
                 <h1>This link is invalid.</h1> \
                 </body> \
                 </html>",
            ));
        }
    };

    let user_id = claims.uid;

    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.verify_user_creation(user_id)
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
                return Ok(HttpResponse::BadRequest().content_type("text/html").body(
                    "<!DOCTYPE html> \
                     <html> \
                     <head> \
                     <title>Entries App User Verification</title> \
                     </head> \
                     <body> \
                     <h1>Could not find the correct account. This is probably an error on our part.</h1> \
                     <h3>We apologize. We'll try to fix this. Please try again in a few hours.</h3> \
                     </body> \
                     </html>",
                ));
            }
            _ => {
                log::error!("{}", e);
                return Ok(HttpResponse::InternalServerError()
                    .content_type("text/html")
                    .body(
                        "<!DOCTYPE html> \
                     <html> \
                     <head> \
                     <title>Entries App User Verification</title> \
                     </head> \
                     <body> \
                     <h1>Could not verify account due to an error.</h1> \
                     <h3>We're sorry. We'll try to fix this. Please try again in a few hours.</h3> \
                     </body> \
                     </html>",
                    ));
            }
        },
    };

    Ok(HttpResponse::Ok().content_type("text/html").body(format!(
        "<!DOCTYPE html> \
             <html> \
             <head> \
             <title>The Budget App User Verification</title> \
             </head> \
             <body> \
             <h1>User verified</h1> \
             <h3>User email address: {}</h3> \
             <h2>You can now sign into the app using your email address and password.</h2> \
             <h2>Happy budgeting!</h2> \
             </body> \
             </html>",
        claims.eml,
    )))
}

pub async fn edit_preferences(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    new_prefs: web::Json<InputEditUserPrefs>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.update_user_prefs(
            user_access_token.claims.user_id,
            &new_prefs.encrypted_blob,
            &new_prefs.expected_previous_data_hash,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::OutOfDateHash => {
                return Err(ServerError::InputRejected(Some(String::from(
                    "Out of date hash",
                ))));
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No user with provided ID",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to update user preferences",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn edit_keystore(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    new_keystore: web::Json<InputEditUserKeystore>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.update_user_keystore(
            user_access_token.claims.user_id,
            &new_keystore.encrypted_blob,
            &new_keystore.expected_previous_data_hash,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::OutOfDateHash => {
                return Err(ServerError::InputRejected(Some(String::from(
                    "Out of date hash",
                ))));
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No user with provided ID",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to update user keystore",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn change_password(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    new_password_data: web::Json<InputNewAuthStringAndEncryptedPassword>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
    let current_auth_string = new_password_data.current_auth_string.clone();

    let does_current_auth_match = web::block(move || {
        let hash_and_attempts = match auth_dao.get_user_auth_string_hash_and_mark_attempt(
            &user_access_token.claims.eml,
            env::CONF.security.authorization_attempts_reset_time,
        ) {
            Ok(a) => a,
            Err(e) => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to check authorization attempt count",
                ))));
            }
        };

        if hash_and_attempts.attempt_count > env::CONF.security.authorization_max_attempts
            && hash_and_attempts.expiration_time >= SystemTime::now()
        {
            return Err(ServerError::AccessForbidden(Some(String::from(
                "Too many login attempts. Try again in a few minutes.",
            ))));
        }

        Ok(argon2_hasher::verify_hash(
            &current_auth_string,
            &hash_and_attempts.auth_string_hash,
            &env::CONF.keys.hashing_key,
        ))
    })
    .await??;

    if !does_current_auth_match {
        return Err(ServerError::UserUnauthorized(Some(String::from(
            "Current auth string was incorrect",
        ))));
    }

    web::block(move || {
        let _auth_string_hash = {
            argon2_hasher::hash_auth_string(
                &new_password_data.new_auth_string,
                &argon2_hasher::HashParams {
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
            user_access_token.user_id,
            &new_password_data.0.new_auth_string,
            &new_password_data.0.auth_string_salt,
            new_password_data.0.auth_string_iters,
            &new_password_data.0.encrypted_encryption_key,
        )
    })
    .await
    .map(|_| HttpResponse::Ok().finish())
    .map_err(|e| {
        log::error!("{}", e);
        ServerError::DatabaseTransactionError(Some(String::from("Failed to update password")))
    })
}

// TODO: Initiate reset password by sending an email with a code ("forgot password")
// TODO: This endpoint should be debounced and not send more than one email to a given address
//       per minutex

// TODO: Need to get list of budget tokens and validate them
pub async fn init_delete(
    user_access_token: VerifiedToken<Access, FromHeader>,
) -> Result<HttpResponse, ServerError> {
    let mut user_deletion_token = AuthToken::new(
        user_access_token.0.user_id,
        &user_access_token.0.user_email,
        SystemTime::now() + env::CONF.lifetimes.user_deletion_token_lifetime,
        AuthTokenType::UserDeletion,
    );

    user_deletion_token.encrypt(&env::CONF.keys.token_encryption_cipher);
    let user_deletion_token =
        user_deletion_token.sign_and_encode(&env::CONF.keys.token_signing_key);

    // TODO: Don't print user deletion token; email it!
    println!("\n\nUser Deletion Token: {user_deletion_token}\n\n");

    Ok(HttpResponse::Created().json(OutputVerificationEmailSent {
        email_sent: true,
        email_token_lifetime_hours: env::CONF.lifetimes.user_deletion_token_lifetime.as_secs()
            / 3600,
    }))
}

pub async fn delete(
    db_thread_pool: web::Data<DbThreadPool>,
    user_deletion_token: UnverifiedToken<UserDeletion, FromQuery>,
) -> Result<HttpResponse, ServerError> {
    let claims = match user_deletion_token.verify() {
        Ok(c) => c,
        Err(TokenError::TokenExpired) => {
            return Ok(HttpResponse::BadRequest().content_type("text/html").body(
                "<!DOCTYPE html> \
                 <html> \
                 <head> \
                 <title>Entries App User Deletion</title> \
                 </head> \
                 <body> \
                 <h1>This link has expired. You will need initiate the deletion process again.</h1> \
                 \
                 <script> \
                 const urlQueries = new URLSearchParams(window.location.search); \
                 const token = urlQueries.get('UserDeletionToken'); \
                 \
                 if (token !== null) { \
                 const decoded_token = atob(token); \
                 const claims = JSON.parse(decoded_token); \
                 \
                 if (claims['exp'] !== null) { \
                 const hourAfterExpiration = claims['exp'] + 3600; \
                 const accountAvailableForDelete = new Date(hourAfterExpiration * 1000); \
                 const now = new Date(); \
                 \
                 if (accountAvailableForDelete > now) { \
                 let deleteMessage = document.createElement('h3'); \
                 \
                 const millisUntilCanDelete = Math.abs(now - accountAvailableForDelete); \
                 const minsUntilCanDelete = Math.ceil((millisUntilCanDelete / 1000) / 60); \
                 \
                 const timeString = minsUntilCanDelete > 1 \
                 ? minsUntilCanDelete + ' minutes.' \
                 : '1 minute.' \
                 \
                 deleteMessage.innerHTML = 'You can re-initate deletion of your account in ' \
                 + timeString; \
                 \
                 document.body.appendChild(deleteMessage); \
                 } \
                 } \
                 } \
                 </script> \
                 </body> \
                 </html>"
            ));
        }
        Err(TokenError::TokenMissing) => {
            return Ok(HttpResponse::BadRequest().content_type("text/html").body(
                "<!DOCTYPE html> \
                 <html> \
                 <head> \
                 <title>Entries App User Deletion</title> \
                 </head> \
                 <body> \
                 <h1>This link is invalid because it is missing a token.</h1> \
                 </body> \
                 </html>",
            ));
        }
        Err(TokenError::TokenExpired) | Err(TokenError::WrongTokenType) => {
            return Ok(HttpResponse::BadRequest().content_type("text/html").body(
                "<!DOCTYPE html> \
                 <html> \
                 <head> \
                 <title>Entries App User Deletion</title> \
                 </head> \
                 <body> \
                 <h1>This link is invalid.</h1> \
                 </body> \
                 </html>",
            ));
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
                return Ok(HttpResponse::BadRequest().content_type("text/html").body(
                    "<!DOCTYPE html> \
                               <html> \
                               <head> \
                               <title>Entries App Account Deletion</title> \
                               </head> \
                               <body> \
                               <h1>Account is already scheduled to be deleted.</h1> \
                               </body> \
                               </html>",
                ));
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                log::error!(
                    "Failed to schedule user deletion after validating UserDeletionToken: {}",
                    e
                );
                return Ok(HttpResponse::BadRequest().content_type("text/html").body(
                    "<!DOCTYPE html> \
                     <html> \
                     <head> \
                     <title>Entries App User Deletion</title> \
                     </head> \
                     <body> \
                     <h1>Could not find the correct account. This is probably an error on our part.</h1> \
                     <h3>We apologize. We'll try to fix this. Please try again in a few hours.</h3> \
                     </body> \
                     </html>",
                ));
            }
            _ => {
                log::error!("{}", e);
                return Ok(HttpResponse::InternalServerError()
                          .content_type("text/html")
                          .body(
                              "<!DOCTYPE html> \
                               <html> \
                               <head> \
                               <title>Entries App Account Deletion</title> \
                               </head> \
                               <body> \
                               <h1>Could not verify account deletion due to an error.</h1> \
                               <h2>We're sorry. We'll try to fix this. Please try again in a few hours.</h2> \
                               </body> \
                               </html>"
                          ));
            }
        },
    };

    Ok(HttpResponse::Ok().content_type("text/html").body(format!(
        "<!DOCTYPE html> \
         <html> \
         <head> \
         <title>Entries App Account Deletion</title> \
         </head> \
         <body> \
         <h1>Your account has been scheduled for deletion.</h1> \
         <h2>User email address: {}</h2> \
         <h2>Your account will be deleted in about {} days. You can cancel your account deletion from the app.</h2> \
         </body> \
         </html>",
        claims.eml,
        days_until_deletion,
    )))
}

pub async fn is_listed_for_deletion(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    let is_listed_for_deletion = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.check_is_user_listed_for_deletion(user_access_token.claims.user_id)
    })
    .await?
    {
        Ok(l) => l,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No user with provided ID",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to cancel user deletion",
                ))));
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
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.cancel_user_deletion(user_access_token.claims.user_id)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No user with provided ID",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to cancel user deletion",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}
