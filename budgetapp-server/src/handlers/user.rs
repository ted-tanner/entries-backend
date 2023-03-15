use budgetapp_utils::db::{DaoError, DbThreadPool};
use budgetapp_utils::request_io::{
    InputEditUserPrefs, InputNewAuthStringAndEncryptedPassword, InputToken, InputUser,
    OutputIsUserListedForDeletion, OutputVerificationEmailSent,
};
use budgetapp_utils::validators::{self, Validity};
use budgetapp_utils::{argon2_hasher, auth_token, db};

use actix_web::{web, HttpResponse};
use std::time::{Duration, SystemTime};

use crate::env;
use crate::handlers::error::ServerError;
use crate::middleware::auth::AuthorizedUserClaims;

pub async fn create(
    db_thread_pool: web::Data<DbThreadPool>,
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
        user_dao.create_user(user_data.0, &auth_string_hash)
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

    let user_creation_token = auth_token::generate_token(
        &auth_token::TokenParams {
            user_id,
            user_email: &email,
        },
        auth_token::TokenType::UserCreation,
        env::CONF.lifetimes.user_creation_token_lifetime,
        &env::CONF.keys.token_signing_key,
        &env::CONF.keys.token_encryption_cipher,
    );

    let user_creation_token = match user_creation_token {
        Ok(t) => t,
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::InternalError(Some(String::from(
                "Failed to generate user creation token",
            ))));
        }
    };

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
    user_creation_token: web::Query<InputToken>,
) -> Result<HttpResponse, ServerError> {
    let claims = match auth_token::validate_token(
        user_creation_token.token.as_str(),
        auth_token::TokenType::UserCreation,
        &env::CONF.keys.token_signing_key,
        &env::CONF.keys.token_encryption_cipher,
    ) {
        Ok(c) => c,
        Err(e) => match e {
            auth_token::TokenError::TokenInvalid | auth_token::TokenError::WrongTokenType => {
                return Ok(HttpResponse::BadRequest().content_type("text/html").body(
                    "<!DOCTYPE html> \
                     <html> \
                     <head> \
                     <title>The Budget App User Verification</title> \
                     </head> \
                     <body> \
                     <h1>Could not verify account. Is the URL correct?</h1> \
                     </body> \
                     </html>",
                ));
            }
            auth_token::TokenError::TokenExpired => {
                return Ok(HttpResponse::BadRequest().content_type("text/html").body(
                    "<!DOCTYPE html> \
                     <html> \
                     <head> \
                     <title>The Budget App User Verification</title> \
                     </head> \
                     <body> \
                     <h1>This link has expired. You will need to recreate your account.</h1> \
                     </body> \
                     </html>",
                ));
            }
            e => {
                log::error!("User verification endpoint: {}", e);
                return Ok(HttpResponse::InternalServerError()
                    .content_type("text/html")
                    .body(
                        "<!DOCTYPE html> \
                     <html> \
                     <head> \
                     <title>The Budget App User Verification</title> \
                     </head> \
                     <body> \
                     <h1>Could not verify account due to an error.</h1> \
                     <h2>We're sorry. We'll try to fix this. Please try again in a few hours.</h2> \
                     </body> \
                     </html>",
                    ));
            }
        },
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
                return Ok(HttpResponse::BadRequest().content_type("text/html").body(
                    "<!DOCTYPE html> \
                     <html> \
                     <head> \
                     <title>The Budget App User Verification</title> \
                     </head> \
                     <body> \
                     <h1>Could not find the correct account. Is the URL correct?</h1> \
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
                     <title>The Budget App User Verification</title> \
                     </head> \
                     <body> \
                     <h1>Could not verify account due to an error.</h1> \
                     <h2>We're sorry. We'll try to fix this. Please try again in a few hours.</h2> \
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
             <h2>User email address: {}</h2> \
             <h2>You can now sign into The Budget App using your email address and password.</h2> \
             <h2>Happy budgeting!</h2> \
             </body> \
             </html>",
        claims.eml,
    )))
}

pub async fn edit_preferences(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    new_prefs: web::Json<InputEditUserPrefs>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.update_user_prefs(auth_user_claims.0.uid, &new_prefs.encrypted_blob_b64)
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
                    "Failed to update user preferences",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn change_password(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    new_password_data: web::Json<InputNewAuthStringAndEncryptedPassword>,
) -> Result<HttpResponse, ServerError> {
    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
    let current_auth_string = new_password_data.current_auth_string.clone();

    let does_current_auth_match = web::block(move || {
        let hash_and_attempts = match auth_dao.get_user_auth_string_hash_and_mark_attempt(
            &auth_user_claims.0.eml,
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
            auth_user_claims.0.uid,
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
// TODO: This endpoint should be throttled by email

pub async fn init_delete(
    auth_user_claims: AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let user_deletion_token = {
        auth_token::generate_token(
            &auth_token::TokenParams {
                user_id: auth_user_claims.0.uid,
                user_email: &auth_user_claims.0.eml,
            },
            auth_token::TokenType::UserDeletion,
            env::CONF.lifetimes.user_deletion_token_lifetime,
            &env::CONF.keys.token_signing_key,
            &env::CONF.keys.token_encryption_cipher,
        )
    };

    let user_deletion_token = match user_deletion_token {
        Ok(t) => t,
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::InternalError(Some(String::from(
                "Failed to generate user deletion token",
            ))));
        }
    };

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
    user_deletion_token: web::Query<InputToken>,
) -> Result<HttpResponse, ServerError> {
    let claims = match auth_token::validate_token(
        user_deletion_token.token.as_str(),
        auth_token::TokenType::UserDeletion,
        &env::CONF.keys.token_signing_key,
        &env::CONF.keys.token_encryption_cipher,
    ) {
        Ok(c) => c,
        Err(e) => match e {
            auth_token::TokenError::TokenInvalid | auth_token::TokenError::WrongTokenType => {
                return Ok(HttpResponse::BadRequest().content_type("text/html").body(
                    "<!DOCTYPE html> \
                         <html> \
                         <head> \
                         <title>The Budget App Account Deletion</title> \
                         </head> \
                         <body> \
                         <h1>Could not verify account deletion. Is the URL correct?</h1> \
                         </body> \
                         </html>",
                ));
            }
            auth_token::TokenError::TokenExpired => {
                return Ok(HttpResponse::BadRequest().content_type("text/html").body(
                    "<!DOCTYPE html> \
                               <html> \
                               <head> \
                               <title>The Budget App Account Deletion</title> \
                               </head> \
                               <body> \
                               <h1>This link has expired.</h1> \
                               </body> \
                               </html>",
                ));
            }
            e => {
                log::error!("User deletion endpoint: {}", e);
                return Ok(HttpResponse::InternalServerError()
                          .content_type("text/html")
                          .body("<!DOCTYPE html> \
                               <html> \
                               <head> \
                               <title>The Budget App Account Deletion</title> \
                               </head> \
                               <body> \
                               <h1>Could not verify account deletion due to an error.</h1> \
                               <h2>We're sorry. We'll try to fix this. Please try again in a few hours.</h2> \
                               </body> \
                               </html>"));
            }
        },
    };

    let user_id = claims.uid;
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
                               <title>The Budget App Account Deletion</title> \
                               </head> \
                               <body> \
                               <h1>Account is already scheduled to be deleted.</h1> \
                               </body> \
                               </html>",
                ));
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Ok(HttpResponse::BadRequest().content_type("text/html").body(
                    "<!DOCTYPE html> \
                               <html> \
                               <head> \
                               <title>The Budget App Account Deletion</title> \
                               </head> \
                               <body> \
                               <h1>Could not find the correct account. Is the URL correct?</h1> \
                               </body> \
                               </html>",
                ));
            }
            _ => {
                log::error!("{}", e);
                return Ok(HttpResponse::InternalServerError()
                          .content_type("text/html")
                          .body("<!DOCTYPE html> \
                               <html> \
                               <head> \
                               <title>The Budget App Account Deletion</title> \
                               </head> \
                               <body> \
                               <h1>Could not verify account deletion due to an error.</h1> \
                               <h2>We're sorry. We'll try to fix this. Please try again in a few hours.</h2> \
                               </body> \
                               </html>"));
            }
        },
    };

    Ok(HttpResponse::Ok().content_type("text/html").body(format!(
        "<!DOCTYPE html> \
         <html> \
         <head> \
         <title>The Budget App Account Deletion</title> \
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
    auth_user_claims: AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let is_listed_for_deletion = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.check_is_user_listed_for_deletion(auth_user_claims.0.uid)
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
    auth_user_claims: AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.cancel_user_deletion(auth_user_claims.0.uid)
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
