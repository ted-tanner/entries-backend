use budgetapp_utils::db::{DaoError, DbThreadPool};
use budgetapp_utils::request_io::{
    InputBuddyRequest, InputBuddyRequestId, InputEditUserPrefs, InputEmail,
    InputNewAuthStringAndEncryptedPassword, InputOptionalUserId, InputToken, InputUser,
    InputUserId, OutputEmail, OutputIsUserListedForDeletion, OutputVerificationEmailSent,
};
use budgetapp_utils::validators::{self, Validity};
use budgetapp_utils::{argon2_hasher, auth_token, db};

use actix_web::{web, HttpResponse};
use std::time::{Duration, SystemTime};

use crate::env;
use crate::handlers::error::ServerError;
use crate::middleware::auth::AuthorizedUserClaims;

pub async fn get_user_email(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    user_id: web::Query<InputOptionalUserId>,
) -> Result<HttpResponse, ServerError> {
    let user_id = user_id.user_id.unwrap_or(auth_user_claims.0.uid);

    let email = if user_id == auth_user_claims.0.uid {
        auth_user_claims.0.eml
    } else {
        match web::block(move || {
            let mut user_dao = db::user::Dao::new(&db_thread_pool);
            user_dao.get_user_email(user_id)
        })
        .await?
        {
            Ok(eml) => eml,
            Err(e) => match e {
                DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                    return Err(ServerError::NotFound(Some(String::from("User not found"))))
                }
                _ => {
                    log::error!("{}", e);
                    return Err(ServerError::DatabaseTransactionError(Some(String::from(
                        "Failed to get user email",
                    ))));
                }
            },
        }
    };

    Ok(HttpResponse::Ok().json(OutputEmail { email }))
}

pub async fn lookup_user_id_by_email(
    db_thread_pool: web::Data<DbThreadPool>,
    _auth_user_claims: AuthorizedUserClaims,
    email: web::Query<InputEmail>,
) -> Result<HttpResponse, ServerError> {
    if let Validity::Invalid(msg) = validators::validate_email_address(&email.email) {
        return Err(ServerError::InvalidFormat(Some(msg)));
    }

    let email_clone = email.email.clone();

    let _id = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.lookup_user_id_by_email(&email.email)
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from("User not found"))))
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to get user ID",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().json(OutputEmail { email: email_clone }))
}

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
            &env::AUTH_STRING_HASHING_PARAMS,
            env::CONF.keys.hashing_key.as_bytes(),
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

    let token_lifetime_hours = env::CONF.lifetimes.user_creation_token_lifetime_days * 24;
    let user_creation_token = auth_token::generate_token(
        &auth_token::TokenParams {
            user_id: user_id,
            user_email: &email,
        },
        auth_token::TokenType::UserCreation,
        Duration::from_secs(token_lifetime_hours * 60 * 60),
        env::CONF.keys.token_signing_key.as_bytes(),
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
        email_token_lifetime_hours: token_lifetime_hours,
    }))
}

pub async fn verify_creation(
    db_thread_pool: web::Data<DbThreadPool>,
    user_creation_token: web::Query<InputToken>,
) -> Result<HttpResponse, ServerError> {
    let claims = match auth_token::validate_token(
        user_creation_token.token.as_str(),
        auth_token::TokenType::UserCreation,
        env::CONF.keys.token_signing_key.as_bytes(),
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
    new_prefs: web::Query<InputEditUserPrefs>,
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
            Duration::from_secs(env::CONF.security.authorization_attempts_reset_mins * 60),
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
            env::CONF.keys.hashing_key.as_bytes(),
        ))
    })
    .await??;

    if !does_current_auth_match {
        return Err(ServerError::UserUnauthorized(Some(String::from(
            "Current auth string was incorrect",
        ))));
    }

    web::block(move || {
        let _auth_string_hash = argon2_hasher::hash_auth_string(
            &new_password_data.new_auth_string,
            &env::AUTH_STRING_HASHING_PARAMS,
            env::CONF.keys.hashing_key.as_bytes(),
        );

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

pub async fn send_buddy_request(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    buddy_request: web::Json<InputBuddyRequest>,
) -> Result<HttpResponse, ServerError> {
    if buddy_request.other_user_id == auth_user_claims.0.uid {
        return Err(ServerError::InputRejected(Some(String::from(
            "Requester and recipient have the same ID",
        ))));
    }

    let mut user_dao = db::user::Dao::new(&db_thread_pool);

    match web::block(move || {
        user_dao.send_buddy_request(
            buddy_request.0.other_user_id,
            auth_user_claims.0.uid,
            buddy_request.0.sender_name_encrypted_b64.as_deref(),
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
                return Err(ServerError::InputRejected(Some(String::from(
                    "Request was already sent",
                ))));
            }
            DaoError::WontRunQuery => {
                return Err(ServerError::InputRejected(Some(String::from(
                    "Sender and recipient are already buddies",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to create buddy request",
                ))));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn retract_buddy_request(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    request_id: web::Query<InputBuddyRequestId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.delete_buddy_request(request_id.buddy_request_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(_) => (),
        Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
            return Err(ServerError::NotFound(Some(String::from(
                "No buddy request with provided ID was made by user",
            ))));
        }
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to delete request",
            ))));
        }
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn accept_buddy_request(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    request_id: web::Query<InputBuddyRequestId>,
) -> Result<HttpResponse, ServerError> {
    let request_id = request_id.buddy_request_id;
    let mut user_dao = db::user::Dao::new(&db_thread_pool);

    let _buddy_request_data =
        match web::block(move || user_dao.accept_buddy_request(request_id, auth_user_claims.0.uid))
            .await?
        {
            Ok(req_data) => req_data,
            Err(e) => match e {
                DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                    return Err(ServerError::NotFound(Some(String::from(
                        "No buddy request with provided ID",
                    ))));
                }
                _ => {
                    log::error!("{}", e);
                    return Err(ServerError::DatabaseTransactionError(Some(String::from(
                        "Failed to accept buddy request",
                    ))));
                }
            },
        };

    Ok(HttpResponse::Ok().finish())
}

pub async fn decline_buddy_request(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    request_id: web::Query<InputBuddyRequestId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.delete_buddy_request(request_id.buddy_request_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(_) => (),
        Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
            return Err(ServerError::NotFound(Some(String::from(
                "No buddy request exists with provided ID",
            ))));
        }
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to decline request",
            ))));
        }
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn get_all_pending_buddy_requests_for_user(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let requests = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.get_all_pending_buddy_requests_for_user(auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(reqs) => reqs,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No buddy requests for user",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to find buddy requests",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().json(requests))
}

pub async fn get_all_pending_buddy_requests_made_by_user(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let requests = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.get_all_pending_buddy_requests_made_by_user(auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(reqs) => reqs,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No buddy requests made by user",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to find buddy requests",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().json(requests))
}

pub async fn get_buddy_request(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    request_id: web::Query<InputBuddyRequestId>,
) -> Result<HttpResponse, ServerError> {
    let request = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        // The user DAO returns a diesel::result::Error::NotFound if requestor isn't the sender
        // or recipient
        user_dao.get_buddy_request(request_id.buddy_request_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(req) => req,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "Buddy request not found",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to find buddy request",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().json(request))
}

pub async fn delete_buddy_relationship(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    other_user_id: web::Query<InputUserId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.delete_buddy_relationship(auth_user_claims.0.uid, other_user_id.user_id)
    })
    .await?
    {
        Ok(_) => (),
        Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
            return Err(ServerError::NotFound(Some(String::from(
                "Buddy relationship not found",
            ))));
        }
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to delete buddy relationship",
            ))));
        }
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn get_buddies(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let buddies = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.get_buddies(auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to find buddies for user",
            ))));
        }
    };

    Ok(HttpResponse::Ok().json(buddies))
}

pub async fn init_delete(
    auth_user_claims: AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let token_lifetime_hours = env::CONF.lifetimes.user_deletion_token_lifetime_days * 24;
    let user_deletion_token = auth_token::generate_token(
        &auth_token::TokenParams {
            user_id: auth_user_claims.0.uid,
            user_email: &auth_user_claims.0.eml,
        },
        auth_token::TokenType::UserDeletion,
        Duration::from_secs(token_lifetime_hours * 60 * 60),
        env::CONF.keys.token_signing_key.as_bytes(),
    );

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
        email_token_lifetime_hours: token_lifetime_hours,
    }))
}

pub async fn delete(
    db_thread_pool: web::Data<DbThreadPool>,
    user_deletion_token: web::Query<InputToken>,
) -> Result<HttpResponse, ServerError> {
    let claims = match auth_token::validate_token(
        user_deletion_token.token.as_str(),
        auth_token::TokenType::UserDeletion,
        env::CONF.keys.token_signing_key.as_bytes(),
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
