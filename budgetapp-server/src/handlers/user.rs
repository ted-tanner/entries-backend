use budgetapp_utils::db::{DaoError, DbThreadPool};
use budgetapp_utils::request_io::{
    CurrentAndNewPasswordPair, InputBuddyRequestId, InputEditUser, InputOptionalUserId, InputUser,
    InputUserId, OutputUserForBuddies, OutputUserPrivate, OutputUserPublic, SigninToken,
};
use budgetapp_utils::validators::{self, Validity};
use budgetapp_utils::{auth_token, db, otp, password_hasher};

use actix_web::{web, HttpRequest, HttpResponse};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::env;
use crate::handlers::error::ServerError;
use crate::middleware;

pub async fn get(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    input_user_data: web::Query<InputOptionalUserId>,
) -> Result<HttpResponse, ServerError> {
    let user_id = input_user_data.user_id.unwrap_or(auth_user_claims.0.uid);

    let db_thread_pool_clone = db_thread_pool.clone();

    let user = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool_clone);
        user_dao.get_user_by_id(user_id)
    })
    .await?
    {
        Ok(u) => u,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::InvalidCString(_))
            | DaoError::QueryFailure(diesel::result::Error::DeserializationError(_)) => {
                return Err(ServerError::InvalidFormat(None))
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from("User not found"))))
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to get user data",
                ))));
            }
        },
    };

    if user.id == auth_user_claims.0.uid {
        let output_user = OutputUserPrivate {
            id: user.id,
            is_active: user.is_active,
            is_premium: user.is_premium,
            premium_expiration: user.premium_expiration,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            date_of_birth: user.date_of_birth,
            currency: user.currency,
            modified_timestamp: user.modified_timestamp,
            created_timestamp: user.created_timestamp,
        };

        return Ok(HttpResponse::Ok().json(output_user));
    }

    let are_buddies = if let Some(true) = input_user_data.get_buddy_profile {
        check_are_buddies(&db_thread_pool, auth_user_claims.0.uid, user.id).await?
    } else {
        false
    };

    if are_buddies {
        let output_user = OutputUserForBuddies {
            id: user.id,
            is_active: user.is_active,
            is_premium: user.is_premium,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            currency: user.currency,
        };

        Ok(HttpResponse::Ok().json(output_user))
    } else {
        let output_user = OutputUserPublic {
            id: user.id,
            is_active: user.is_active,
            first_name: user.first_name,
            last_name: user.last_name,
            currency: user.currency,
        };

        Ok(HttpResponse::Ok().json(output_user))
    }
}

pub async fn get_user_by_email(
    req: HttpRequest,
    db_thread_pool: web::Data<DbThreadPool>,
    _auth_user_claims: middleware::auth::AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    // Using a header to accept email address so email address gets encrypted over HTTPS (it
    // wouldn't if sent in URL query) and so a payload doesn't need to be sent with an HTTP
    // GET request
    let email_addr = if let Some(email_val) = req.headers().get("user-email") {
        if let Ok(email) = email_val.to_str() {
            if !validators::validate_email_address(email).is_valid() {
                return Err(ServerError::InputRejected(Some(String::from(
                    "Invalid email address",
                ))));
            }

            String::from(email)
        } else {
            return Err(ServerError::InputRejected(Some(String::from(
                "Invalid email address",
            ))));
        }
    } else {
        return Err(ServerError::InvalidFormat(Some(String::from(
            "user-email header not provided",
        ))));
    };

    let user = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.get_user_by_email(&email_addr)
    })
    .await?
    {
        Ok(u) => u,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::InvalidCString(_))
            | DaoError::QueryFailure(diesel::result::Error::DeserializationError(_)) => {
                return Err(ServerError::InvalidFormat(None))
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from("User not found"))))
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to get user data",
                ))));
            }
        },
    };

    let output_user = OutputUserPublic {
        id: user.id,
        is_active: user.is_active,
        first_name: user.first_name,
        last_name: user.last_name,
        currency: user.currency,
    };

    Ok(HttpResponse::Ok().json(output_user))
}

pub async fn create(
    db_thread_pool: web::Data<DbThreadPool>,
    user_data: web::Json<InputUser>,
) -> Result<HttpResponse, ServerError> {
    if !user_data.0.validate_email_address().is_valid() {
        return Err(ServerError::InvalidFormat(Some(String::from(
            "Invalid email address",
        ))));
    }

    if let Validity::Invalid(msg) = user_data
        .0
        .validate_strong_password(env::CONF.security.password_min_len_chars)
    {
        return Err(ServerError::InputRejected(Some(msg)));
    }

    let user = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.create_user(
            &user_data,
            &env::PASSWORD_HASHING_PARAMS,
            env::CONF.keys.hashing_key.as_bytes(),
        )
    })
    .await?
    {
        Ok(u) => u,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::InvalidCString(_))
            | DaoError::QueryFailure(diesel::result::Error::DeserializationError(_)) => {
                return Err(ServerError::InvalidFormat(None));
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::AccessForbidden(Some(String::from(
                    "No user with ID",
                ))));
            }
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

    let signin_token = auth_token::generate_signin_token(
        &auth_token::TokenParams {
            user_id: &user.id,
            user_email: &user.email,
            user_currency: &user.currency,
        },
        Duration::from_secs(env::CONF.lifetimes.signin_token_lifetime_mins * 60),
        env::CONF.keys.token_signing_key.as_bytes(),
    );

    let signin_token = match signin_token {
        Ok(signin_token) => signin_token,
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::InternalError(Some(String::from(
                "Failed to generate sign-in token for user",
            ))));
        }
    };

    let signin_token = SigninToken {
        signin_token: signin_token.to_string(),
    };

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Failed to fetch system time")
        .as_secs();

    let otp = match otp::generate_otp(
        user.id,
        current_time + env::CONF.lifetimes.otp_lifetime_mins * 60,
        Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
        env::CONF.keys.otp_key.as_bytes(),
    ) {
        Ok(p) => p,
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::InternalError(Some(String::from(
                "Failed to generate OTP",
            ))));
        }
    };

    // TODO: Don't log this, email it!
    println!("\n\nOTP: {}\n\n", &otp);

    Ok(HttpResponse::Created().json(signin_token))
}

pub async fn edit(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    user_data: web::Json<InputEditUser>,
) -> Result<HttpResponse, ServerError> {
    web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.edit_user(auth_user_claims.0.uid, &user_data)
    })
    .await
    .map(|_| HttpResponse::Ok().finish())
    .map_err(|e| {
        log::error!("{}", e);
        ServerError::DatabaseTransactionError(Some(String::from("Failed to edit user")))
    })
}

pub async fn change_password(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    password_pair: web::Json<CurrentAndNewPasswordPair>,
) -> Result<HttpResponse, ServerError> {
    let db_thread_pool_clone = db_thread_pool.clone();

    let user = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool_clone);
        user_dao.get_user_by_id(auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(u) => u,
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::InputRejected(Some(String::from(
                "User not found",
            ))));
        }
    };

    let current_password = password_pair.current_password.clone();

    let does_password_match_hash = web::block(move || {
        password_hasher::verify_hash(
            &current_password,
            &user.password_hash,
            env::CONF.keys.hashing_key.as_bytes(),
        )
    })
    .await?;

    if !does_password_match_hash {
        return Err(ServerError::UserUnauthorized(Some(String::from(
            "Current password was incorrect",
        ))));
    }

    let new_password_validity = validators::validate_strong_password(
        &password_pair.new_password,
        &user.email,
        &user.first_name,
        &user.last_name,
        env::CONF.security.password_min_len_chars,
    );

    if let Validity::Invalid(msg) = new_password_validity {
        return Err(ServerError::InputRejected(Some(msg)));
    };

    web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.change_password(
            auth_user_claims.0.uid,
            &password_pair.new_password,
            &env::PASSWORD_HASHING_PARAMS,
            env::CONF.keys.hashing_key.as_bytes(),
        )
    })
    .await
    .map(|_| HttpResponse::Ok().finish())
    .map_err(|e| {
        log::error!("{}", e);
        ServerError::DatabaseTransactionError(Some(String::from("Failed to update password")))
    })
}

pub async fn send_buddy_request(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    other_user_id: web::Json<InputUserId>,
) -> Result<HttpResponse, ServerError> {
    if other_user_id.user_id == auth_user_claims.0.uid {
        return Err(ServerError::InputRejected(Some(String::from(
            "Requester and recipient have the same ID",
        ))));
    }

    let are_buddies = check_are_buddies(
        &db_thread_pool,
        auth_user_claims.0.uid,
        other_user_id.user_id,
    )
    .await?;

    if are_buddies {
        return Err(ServerError::InputRejected(Some(String::from(
            "Sender and recipient are already buddies",
        ))));
    }

    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.send_buddy_request(other_user_id.user_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::InvalidCString(_))
            | DaoError::QueryFailure(diesel::result::Error::DeserializationError(_)) => {
                return Err(ServerError::InvalidFormat(None));
            }
            _ => {
                log::error!("{}", e);
                println!("{}", e);
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
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    request_id: web::Query<InputBuddyRequestId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.delete_buddy_request(request_id.buddy_request_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(count) => {
            if count == 0 {
                return Err(ServerError::NotFound(Some(String::from(
                    "No buddy request with provided ID was made by user",
                ))));
            }
        }
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No buddy request with provided ID",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to delete request",
                ))));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn accept_buddy_request(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    request_id: web::Query<InputBuddyRequestId>,
) -> Result<HttpResponse, ServerError> {
    let db_thread_pool_clone = db_thread_pool.clone();
    let request_id = request_id.buddy_request_id;

    let buddy_request_data = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool_clone);
        user_dao.mark_buddy_request_accepted(request_id, auth_user_claims.0.uid)
    })
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

    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao
            .create_buddy_relationship(buddy_request_data.sender_user_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to accept buddy request",
            ))));
        }
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn decline_buddy_request(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    request_id: web::Query<InputBuddyRequestId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.mark_buddy_request_declined(request_id.buddy_request_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(count) => {
            if count == 0 {
                return Err(ServerError::NotFound(Some(String::from(
                    "No buddy request with provided ID",
                ))));
            }
        }
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No buddy request with provided ID",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to decline buddy request",
                ))));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn get_all_pending_buddy_requests_for_user(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
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
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
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
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    request_id: web::Query<InputBuddyRequestId>,
) -> Result<HttpResponse, ServerError> {
    let request = match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        // The user DAO returns a not found if requestor isn't the sender or recipient
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
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    other_user_id: web::Query<InputUserId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool);
        user_dao.delete_buddy_relationship(auth_user_claims.0.uid, other_user_id.user_id)
    })
    .await?
    {
        Ok(0) | Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
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
        Ok(_) => (),
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn get_buddies(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
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

async fn check_are_buddies(
    db_thread_pool: &DbThreadPool,
    user1_id: Uuid,
    user2_id: Uuid,
) -> Result<bool, ServerError> {
    let db_thread_pool_clone = db_thread_pool.clone();
    match web::block(move || {
        let mut user_dao = db::user::Dao::new(&db_thread_pool_clone);
        user_dao.check_are_buddies(user1_id, user2_id)
    })
    .await?
    {
        Ok(buddies) => Ok(buddies),
        Err(e) => {
            log::error!("{}", e);
            Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to get user data",
            ))))
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use budgetapp_utils::auth_token::TokenClaims;
    use budgetapp_utils::models::buddy_relationship::BuddyRelationship;
    use budgetapp_utils::models::buddy_request::BuddyRequest;
    use budgetapp_utils::models::user::User;
    use budgetapp_utils::request_io::{SigninTokenOtpPair, TokenPair};
    use budgetapp_utils::schema::buddy_relationships as buddy_relationship_fields;
    use budgetapp_utils::schema::buddy_relationships::dsl::buddy_relationships;
    use budgetapp_utils::schema::buddy_requests as buddy_request_fields;
    use budgetapp_utils::schema::buddy_requests::dsl::buddy_requests;
    use budgetapp_utils::schema::users as user_fields;
    use budgetapp_utils::schema::users::dsl::users;

    use actix_web::web::Data;
    use actix_web::{http, test, App};
    use diesel::prelude::*;
    use rand::prelude::*;

    use crate::env;
    use crate::services;

    #[derive(Clone)]
    pub struct UserWithAuthTokens {
        pub user: User,
        pub token_pair: TokenPair,
    }

    pub async fn create_user_and_sign_in() -> UserWithAuthTokens {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("tNmUV%9$khHK2TqOLw*%W"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
            currency: String::from("USD"),
        };

        let create_user_res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
        .await;

        let signin_token = test::read_body_json::<SigninToken, _>(create_user_res).await;
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let mut user_dao = db::user::Dao::new(&env::testing::DB_THREAD_POOL);
        let user = user_dao.get_user_by_id(user_id).unwrap();

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let otp_req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let otp_res = test::call_service(&app, otp_req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(otp_res).await;

        UserWithAuthTokens { user, token_pair }
    }

    #[actix_rt::test]
    async fn test_create() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
            currency: String::from("USD"),
        };

        let req = test::TestRequest::post()
            .uri("/api/user/create")
            .insert_header(("content-type", "application/json"))
            .set_json(&new_user)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::CREATED);

        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let created_user = users
            .filter(user_fields::email.eq(&new_user.email.to_lowercase()))
            .first::<User>(&mut db_connection)
            .unwrap();

        assert_eq!(&new_user.email, &created_user.email);
        assert_ne!(&new_user.password, &created_user.password_hash);
        assert_eq!(&new_user.first_name, &created_user.first_name);
        assert_eq!(&new_user.last_name, &created_user.last_name);
        assert_eq!(&new_user.date_of_birth, &created_user.date_of_birth);
        assert_eq!(&new_user.currency, &created_user.currency);
    }

    #[actix_rt::test]
    async fn test_edit() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("1dIbCx^n@VF9f&0*c*39"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
            currency: String::from("USD"),
        };

        let create_user_res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
        .await;

        let signin_token = test::read_body_json::<SigninToken, _>(create_user_res).await;
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;
        let access_token = token_pair.access_token.to_string();

        let edited_user = InputEditUser {
            first_name: format!("Test-{}-edited", &user_number),
            last_name: new_user.last_name.clone(),
            date_of_birth: new_user.date_of_birth,
            currency: String::from("DOP"),
        };

        let req = test::TestRequest::put()
            .uri("/api/user/edit")
            .insert_header((
                "authorization",
                format!("bearer {}", &access_token).as_str(),
            ))
            .set_json(&edited_user)
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let after_edit_get_req = test::TestRequest::get()
            .uri("/api/user/get")
            .insert_header((
                "authorization",
                format!("bearer {}", &access_token).as_str(),
            ))
            .to_request();

        let after_edit_get_res = test::call_service(&app, after_edit_get_req).await;

        let res_body = String::from_utf8(
            actix_web::test::read_body(after_edit_get_res)
                .await
                .to_vec(),
        )
        .unwrap();
        let user_after_edit = serde_json::from_str::<OutputUserPrivate>(res_body.as_str()).unwrap();

        assert_eq!(&new_user.email, &user_after_edit.email);
        assert_eq!(&new_user.last_name, &user_after_edit.last_name);
        assert_eq!(&new_user.date_of_birth, &user_after_edit.date_of_birth);

        assert_eq!(&edited_user.first_name, &user_after_edit.first_name);
        assert_eq!(&edited_user.currency, &user_after_edit.currency);
    }

    #[actix_rt::test]
    async fn test_create_fails_with_invalid_email() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user = InputUser {
            email: format!("test_user{}test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
            currency: String::from("USD"),
        };

        let req = test::TestRequest::post()
            .uri("/api/user/create")
            .insert_header(("content-type", "application/json"))
            .set_json(&new_user)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn test_create_fails_with_invalid_password() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("Password1234"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
            currency: String::from("USD"),
        };

        let req = test::TestRequest::post()
            .uri("/api/user/create")
            .insert_header(("content-type", "application/json"))
            .set_json(&new_user)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn test_get_no_query_param() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("1dIbCx^n@VF9f&0*c*39"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
            currency: String::from("USD"),
        };

        let create_user_res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
        .await;

        let signin_token = test::read_body_json::<SigninToken, _>(create_user_res).await;
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;
        let access_token = token_pair.access_token.to_string();

        let req = test::TestRequest::get()
            .uri("/api/user/get")
            .insert_header((
                "authorization",
                format!("bearer {}", &access_token).as_str(),
            ))
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(res).await.to_vec()).unwrap();
        let user_from_res = serde_json::from_str::<OutputUserPrivate>(res_body.as_str()).unwrap();

        assert_eq!(&new_user.email, &user_from_res.email);
        assert_eq!(&new_user.first_name, &user_from_res.first_name);
        assert_eq!(&new_user.last_name, &user_from_res.last_name);
        assert_eq!(&new_user.date_of_birth, &user_from_res.date_of_birth);
        assert_eq!(&new_user.currency, &user_from_res.currency);
    }

    #[actix_rt::test]
    async fn test_get_with_query_param() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("1dIbCx^n@VF9f&0*c*39"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
            currency: String::from("USD"),
        };

        let create_user_res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
        .await;

        let signin_token = test::read_body_json::<SigninToken, _>(create_user_res).await;
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;
        let access_token = token_pair.access_token.to_string();

        let other_user = create_user_and_sign_in().await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/user/get?user_id={}", user_id))
            .insert_header((
                "authorization",
                format!("bearer {}", &other_user.token_pair.access_token).as_str(),
            ))
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(res).await.to_vec()).unwrap();
        // Returs public rather than private info if not buddies
        serde_json::from_str::<OutputUserPrivate>(res_body.as_str()).unwrap_err();
        serde_json::from_str::<OutputUserForBuddies>(res_body.as_str()).unwrap_err();
        let user_from_res = serde_json::from_str::<OutputUserPublic>(res_body.as_str()).unwrap();

        assert_eq!(&user_id, &user_from_res.id);
        assert!(user_from_res.is_active);
        assert_eq!(&new_user.first_name, &user_from_res.first_name);
        assert_eq!(&new_user.last_name, &user_from_res.last_name);
        assert_eq!(&new_user.currency, &user_from_res.currency);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get?user_id={}&get_buddy_profile=true",
                user_id
            ))
            .insert_header((
                "authorization",
                format!("bearer {}", &other_user.token_pair.access_token).as_str(),
            ))
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(res).await.to_vec()).unwrap();
        // Returs public rather than private info if not buddies
        serde_json::from_str::<OutputUserPrivate>(res_body.as_str()).unwrap_err();
        serde_json::from_str::<OutputUserForBuddies>(res_body.as_str()).unwrap_err();
        let user_from_res = serde_json::from_str::<OutputUserPublic>(res_body.as_str()).unwrap();

        assert_eq!(&user_id, &user_from_res.id);

        let input_user_id = InputUserId { user_id };

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header((
                "authorization",
                format!("bearer {}", &other_user.token_pair.access_token),
            ))
            .set_json(&input_user_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_request = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(user_id))
            .filter(buddy_request_fields::sender_user_id.eq(&other_user.user.id))
            .first::<BuddyRequest>(&mut db_connection)
            .unwrap();

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/user/accept_buddy_request?buddy_request_id={}",
                created_buddy_request.id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri(&format!("/api/user/get?user_id={}", user_id))
            .insert_header((
                "authorization",
                format!("bearer {}", &other_user.token_pair.access_token).as_str(),
            ))
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(res).await.to_vec()).unwrap();
        serde_json::from_str::<OutputUserPrivate>(res_body.as_str()).unwrap_err();
        serde_json::from_str::<OutputUserForBuddies>(res_body.as_str()).unwrap_err();
        let user_from_res = serde_json::from_str::<OutputUserPublic>(res_body.as_str()).unwrap();

        assert_eq!(&user_id, &user_from_res.id);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get?user_id={}&get_buddy_profile=false",
                user_id
            ))
            .insert_header((
                "authorization",
                format!("bearer {}", &other_user.token_pair.access_token).as_str(),
            ))
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(res).await.to_vec()).unwrap();
        // Returs public rather than private info if not buddies
        serde_json::from_str::<OutputUserPrivate>(res_body.as_str()).unwrap_err();
        serde_json::from_str::<OutputUserForBuddies>(res_body.as_str()).unwrap_err();
        let user_from_res = serde_json::from_str::<OutputUserPublic>(res_body.as_str()).unwrap();

        assert_eq!(&user_id, &user_from_res.id);

        let req = test::TestRequest::get()
            .uri("/api/user/get?get_buddy_profile=true")
            .insert_header((
                "authorization",
                format!("bearer {}", &other_user.token_pair.access_token).as_str(),
            ))
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(res).await.to_vec()).unwrap();
        let user_from_res = serde_json::from_str::<OutputUserPrivate>(res_body.as_str()).unwrap();

        assert_eq!(&other_user.user.id, &user_from_res.id);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get?user_id={}&get_buddy_profile=true",
                user_id
            ))
            .insert_header((
                "authorization",
                format!("bearer {}", &other_user.token_pair.access_token).as_str(),
            ))
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(res).await.to_vec()).unwrap();
        serde_json::from_str::<OutputUserPrivate>(res_body.as_str()).unwrap_err();
        let user_from_res =
            serde_json::from_str::<OutputUserForBuddies>(res_body.as_str()).unwrap();

        assert_eq!(&user_id, &user_from_res.id);
        assert!(user_from_res.is_active);
        assert_eq!(&new_user.email, &user_from_res.email);
        assert_eq!(&new_user.first_name, &user_from_res.first_name);
        assert_eq!(&new_user.last_name, &user_from_res.last_name);
        assert_eq!(&new_user.currency, &user_from_res.currency);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get?user_id={}&get_buddy_profile=true",
                &other_user.user.id
            ))
            .insert_header(("authorization", format!("bearer {access_token}").as_str()))
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(res).await.to_vec()).unwrap();
        serde_json::from_str::<OutputUserPrivate>(res_body.as_str()).unwrap_err();
        let user_from_res =
            serde_json::from_str::<OutputUserForBuddies>(res_body.as_str()).unwrap();

        assert_eq!(&other_user.user.id, &user_from_res.id);
        assert!(user_from_res.is_active);
        assert_eq!(&other_user.user.email, &user_from_res.email);
        assert_eq!(&other_user.user.first_name, &user_from_res.first_name);
        assert_eq!(&other_user.user.last_name, &user_from_res.last_name);
        assert_eq!(&other_user.user.currency, &user_from_res.currency);
    }

    #[actix_rt::test]
    async fn test_get_user_by_email() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("1dIbCx^n@VF9f&0*c*39"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
            currency: String::from("USD"),
        };

        let create_user_res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
        .await;

        let signin_token = test::read_body_json::<SigninToken, _>(create_user_res).await;
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;
        let access_token = token_pair.access_token.to_string();

        let other_user = create_user_and_sign_in().await;

        let req = test::TestRequest::get()
            .uri("/api/user/get_user_by_email")
            .insert_header((
                "authorization",
                format!("bearer {}", &other_user.token_pair.access_token).as_str(),
            ))
            .insert_header(("user-email", other_user.user.email.as_str()))
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(res).await.to_vec()).unwrap();
        // Returs public rather than private info if not buddies
        serde_json::from_str::<OutputUserPrivate>(res_body.as_str()).unwrap_err();
        serde_json::from_str::<OutputUserForBuddies>(res_body.as_str()).unwrap_err();
        let user_from_res = serde_json::from_str::<OutputUserPublic>(res_body.as_str()).unwrap();

        assert_eq!(&other_user.user.id, &user_from_res.id);
        assert!(&other_user.user.is_active);
        assert_eq!(&other_user.user.first_name, &user_from_res.first_name);
        assert_eq!(&other_user.user.last_name, &user_from_res.last_name);
        assert_eq!(&other_user.user.currency, &user_from_res.currency);

        let req = test::TestRequest::get()
            .uri("/api/user/get_user_by_email")
            .insert_header(("authorization", format!("bearer {access_token}").as_str()))
            .insert_header(("user-email", "notarealuseremail@fake.con"))
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);
    }

    #[actix_rt::test]
    async fn test_change_password() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("tNmUV%9$khHK2TqOLw*%W"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
            currency: String::from("USD"),
        };

        let create_user_res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
        .await;

        let signin_token = test::read_body_json::<SigninToken, _>(create_user_res).await;
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;
        let access_token = token_pair.access_token.to_string();

        let password_pair = CurrentAndNewPasswordPair {
            current_password: new_user.password.clone(),
            new_password: String::from("s$B5Pl@KC7t92&a!jZ3Gx"),
        };

        let req = test::TestRequest::put()
            .uri("/api/user/change_password")
            .insert_header(("content-type", "application/json"))
            .insert_header((
                "authorization",
                format!("bearer {}", &access_token).as_str(),
            ))
            .set_payload(serde_json::ser::to_vec(&password_pair).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;

        assert_eq!(res.status(), http::StatusCode::OK);

        let mut user_dao = db::user::Dao::new(&env::testing::DB_THREAD_POOL);
        let db_password_hash = user_dao.get_user_by_id(user_id).unwrap().password_hash;

        assert!(!password_hasher::verify_hash(
            &new_user.password,
            &db_password_hash,
            env::CONF.keys.hashing_key.as_bytes()
        ));
        assert!(password_hasher::verify_hash(
            &password_pair.new_password,
            &db_password_hash,
            env::CONF.keys.hashing_key.as_bytes()
        ));
    }

    #[actix_rt::test]
    async fn test_change_password_current_password_wrong() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("tNmUV%9$khHK2TqOLw*%W"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
            currency: String::from("USD"),
        };

        let create_user_res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
        .await;

        let signin_token = test::read_body_json::<SigninToken, _>(create_user_res).await;
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;
        let access_token = token_pair.access_token.to_string();

        let password_pair = CurrentAndNewPasswordPair {
            current_password: new_user.password.clone() + " ",
            new_password: String::from("s$B5Pl@KC7t92&a!jZ3Gx"),
        };

        let req = test::TestRequest::put()
            .uri("/api/user/change_password")
            .insert_header(("content-type", "application/json"))
            .insert_header((
                "authorization",
                format!("bearer {}", &access_token).as_str(),
            ))
            .set_payload(serde_json::ser::to_vec(&password_pair).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;

        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);

        let mut user_dao = db::user::Dao::new(&env::testing::DB_THREAD_POOL);
        let db_password_hash = user_dao.get_user_by_id(user_id).unwrap().password_hash;

        assert!(password_hasher::verify_hash(
            &new_user.password,
            &db_password_hash,
            env::CONF.keys.hashing_key.as_bytes()
        ));
        assert!(!password_hasher::verify_hash(
            &password_pair.new_password,
            &db_password_hash,
            env::CONF.keys.hashing_key.as_bytes()
        ));
    }

    #[actix_rt::test]
    async fn test_change_password_new_password_invalid() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("tNmUV%9$khHK2TqOLw*%W"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
            currency: String::from("USD"),
        };

        let create_user_res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
        .await;

        let signin_token = test::read_body_json::<SigninToken, _>(create_user_res).await;
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(res).await;
        let access_token = token_pair.access_token.to_string();

        let password_pair = CurrentAndNewPasswordPair {
            current_password: new_user.password.clone(),
            new_password: String::from("Password1234"),
        };

        let req = test::TestRequest::put()
            .uri("/api/user/change_password")
            .insert_header(("content-type", "application/json"))
            .insert_header((
                "authorization",
                format!("bearer {}", &access_token).as_str(),
            ))
            .set_payload(serde_json::ser::to_vec(&password_pair).unwrap())
            .to_request();

        let res = test::call_service(&app, req).await;

        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);

        let mut user_dao = db::user::Dao::new(&env::testing::DB_THREAD_POOL);
        let db_password_hash = user_dao.get_user_by_id(user_id).unwrap().password_hash;

        assert!(password_hasher::verify_hash(
            &new_user.password,
            &db_password_hash,
            env::CONF.keys.hashing_key.as_bytes()
        ));
        assert!(!password_hasher::verify_hash(
            &password_pair.new_password,
            &db_password_hash,
            env::CONF.keys.hashing_key.as_bytes()
        ));
    }

    #[actix_rt::test]
    async fn test_send_buddy_request_and_accept() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1 = create_user_and_sign_in().await;
        let created_user2 = create_user_and_sign_in().await;

        let user1_access_token = created_user1.token_pair.access_token.clone();
        let user2_access_token = created_user2.token_pair.access_token.clone();

        let other_user_id = InputUserId {
            user_id: created_user2.user.id,
        };

        let instant_before_request = SystemTime::now();

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let instant_after_request = SystemTime::now();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);
        assert_eq!(
            created_buddy_requests[0].recipient_user_id,
            created_user2.user.id
        );
        assert_eq!(
            created_buddy_requests[0].sender_user_id,
            created_user1.user.id
        );
        assert!(!created_buddy_requests[0].accepted);

        assert!(created_buddy_requests[0]
            .accepted_declined_timestamp
            .is_none());
        assert!(created_buddy_requests[0].created_timestamp > instant_before_request);
        assert!(created_buddy_requests[0].created_timestamp < instant_after_request);
        assert!(created_buddy_requests[0]
            .accepted_declined_timestamp
            .is_none());

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/user/accept_buddy_request?buddy_request_id={}",
                created_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);
        assert_eq!(
            created_buddy_requests[0].recipient_user_id,
            created_user2.user.id
        );
        assert_eq!(
            created_buddy_requests[0].sender_user_id,
            created_user1.user.id
        );
        assert!(created_buddy_requests[0].accepted);

        assert!(created_buddy_requests[0]
            .accepted_declined_timestamp
            .is_some());
        assert!(created_buddy_requests[0].created_timestamp > instant_before_request);
        assert!(created_buddy_requests[0].created_timestamp < instant_after_request);
        assert!(created_buddy_requests[0]
            .accepted_declined_timestamp
            .is_some());

        let buddy_relationship = buddy_relationships
            .filter(buddy_relationship_fields::user1_id.eq(created_user1.user.id))
            .filter(buddy_relationship_fields::user2_id.eq(created_user2.user.id))
            .first::<BuddyRelationship>(&mut db_connection)
            .unwrap();

        assert_eq!(buddy_relationship.user1_id, created_user1.user.id);
        assert_eq!(buddy_relationship.user2_id, created_user2.user.id);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get?user_id={}&get_buddy_profile=true",
                created_user1.user.id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let user_from_resp =
            serde_json::from_str::<OutputUserForBuddies>(resp_body.as_str()).unwrap();

        assert_eq!(user_from_resp.id, created_user1.user.id);
        assert_eq!(user_from_resp.first_name, created_user1.user.first_name);
        assert_eq!(user_from_resp.last_name, created_user1.user.last_name);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get?user_id={}&get_buddy_profile=true",
                created_user2.user.id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let user_from_resp =
            serde_json::from_str::<OutputUserForBuddies>(resp_body.as_str()).unwrap();

        assert_eq!(user_from_resp.id, created_user2.user.id);
        assert_eq!(user_from_resp.first_name, created_user2.user.first_name);
        assert_eq!(user_from_resp.last_name, created_user2.user.last_name);

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn test_cannot_accept_buddy_requests_for_another_user() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1 = create_user_and_sign_in().await;
        let created_user2 = create_user_and_sign_in().await;
        let created_user3 = create_user_and_sign_in().await;

        let user1_access_token = created_user1.token_pair.access_token.clone();
        let user2_access_token = created_user2.token_pair.access_token.clone();
        let user3_access_token = created_user3.token_pair.access_token.clone();

        let other_user_id = InputUserId {
            user_id: created_user2.user.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/user/accept_buddy_request?buddy_request_id={}",
                created_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);
        assert!(created_buddy_requests[0]
            .accepted_declined_timestamp
            .is_none());
        assert!(!created_buddy_requests[0].accepted);

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/user/accept_buddy_request?buddy_request_id={}",
                created_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);
        assert!(created_buddy_requests[0]
            .accepted_declined_timestamp
            .is_none());
        assert!(!created_buddy_requests[0].accepted);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get?user_id={}&get_buddy_profile=true",
                created_user1.user.id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        serde_json::from_str::<OutputUserForBuddies>(resp_body.as_str()).unwrap_err();

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/user/accept_buddy_request?buddy_request_id={}",
                created_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);
        assert!(created_buddy_requests[0]
            .accepted_declined_timestamp
            .is_some());
        assert!(created_buddy_requests[0].accepted);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get?user_id={}&get_buddy_profile=true",
                created_user1.user.id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        serde_json::from_str::<OutputUserForBuddies>(resp_body.as_str()).unwrap();
    }

    #[actix_rt::test]
    async fn test_send_buddy_request_and_decline() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1 = create_user_and_sign_in().await;
        let created_user2 = create_user_and_sign_in().await;

        let user1_access_token = created_user1.token_pair.access_token.clone();
        let user2_access_token = created_user2.token_pair.access_token.clone();

        let other_user_id = InputUserId {
            user_id: created_user2.user.id,
        };

        let instant_before_request = SystemTime::now();

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let instant_after_request = SystemTime::now();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);
        assert_eq!(
            created_buddy_requests[0].recipient_user_id,
            created_user2.user.id
        );
        assert_eq!(
            created_buddy_requests[0].sender_user_id,
            created_user1.user.id
        );
        assert!(!created_buddy_requests[0].accepted);

        assert!(created_buddy_requests[0]
            .accepted_declined_timestamp
            .is_none());
        assert!(created_buddy_requests[0].created_timestamp > instant_before_request);
        assert!(created_buddy_requests[0].created_timestamp < instant_after_request);
        assert!(created_buddy_requests[0]
            .accepted_declined_timestamp
            .is_none());

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/user/decline_buddy_request?buddy_request_id={}",
                created_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);
        assert_eq!(
            created_buddy_requests[0].recipient_user_id,
            created_user2.user.id
        );
        assert_eq!(
            created_buddy_requests[0].sender_user_id,
            created_user1.user.id
        );
        assert!(!created_buddy_requests[0].accepted);

        assert!(created_buddy_requests[0]
            .accepted_declined_timestamp
            .is_some());
        assert!(created_buddy_requests[0].created_timestamp > instant_before_request);
        assert!(created_buddy_requests[0].created_timestamp < instant_after_request);
        assert!(created_buddy_requests[0]
            .accepted_declined_timestamp
            .is_some());

        buddy_relationships
            .filter(buddy_relationship_fields::user1_id.eq(created_user1.user.id))
            .filter(buddy_relationship_fields::user2_id.eq(created_user2.user.id))
            .first::<BuddyRelationship>(&mut db_connection)
            .unwrap_err();

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get?user_id={}&get_buddy_profile=true",
                created_user1.user.id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        serde_json::from_str::<OutputUserForBuddies>(resp_body.as_str()).unwrap_err();
    }

    #[actix_rt::test]
    async fn test_cannot_decline_buddy_requests_for_another_user() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1 = create_user_and_sign_in().await;
        let created_user2 = create_user_and_sign_in().await;
        let created_user3 = create_user_and_sign_in().await;

        let user1_access_token = created_user1.token_pair.access_token.clone();
        let user2_access_token = created_user2.token_pair.access_token.clone();
        let user3_access_token = created_user3.token_pair.access_token.clone();

        let other_user_id = InputUserId {
            user_id: created_user2.user.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/user/decline_buddy_request?buddy_request_id={}",
                created_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);
        assert!(created_buddy_requests[0]
            .accepted_declined_timestamp
            .is_none());
        assert!(!created_buddy_requests[0].accepted);

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/user/decline_buddy_request?buddy_request_id={}",
                created_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);
        assert!(created_buddy_requests[0]
            .accepted_declined_timestamp
            .is_none());
        assert!(!created_buddy_requests[0].accepted);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get?user_id={}&get_buddy_profile=true",
                created_user1.user.id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        serde_json::from_str::<OutputUserForBuddies>(resp_body.as_str()).unwrap_err();

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/user/decline_buddy_request?buddy_request_id={}",
                created_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);
        assert!(created_buddy_requests[0]
            .accepted_declined_timestamp
            .is_some());
        assert!(!created_buddy_requests[0].accepted);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get?user_id={}&get_buddy_profile=true",
                created_user1.user.id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        serde_json::from_str::<OutputUserForBuddies>(resp_body.as_str()).unwrap_err();
    }

    #[actix_rt::test]
    async fn test_retract_buddy_request() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1 = create_user_and_sign_in().await;
        let created_user2 = create_user_and_sign_in().await;

        let user1_access_token = created_user1.token_pair.access_token.clone();
        let user2_access_token = created_user2.token_pair.access_token.clone();

        let other_user_id = InputUserId {
            user_id: created_user2.user.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/user/retract_buddy_request?buddy_request_id={}",
                created_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 0);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get?user_id={}&get_buddy_profile=true",
                created_user1.user.id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        serde_json::from_str::<OutputUserForBuddies>(resp_body.as_str()).unwrap_err();
    }

    #[actix_rt::test]
    async fn test_cannot_retract_buddy_request_for_another_user() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1 = create_user_and_sign_in().await;
        let created_user2 = create_user_and_sign_in().await;
        let created_user3 = create_user_and_sign_in().await;

        let user1_access_token = created_user1.token_pair.access_token.clone();
        let user2_access_token = created_user2.token_pair.access_token.clone();
        let user3_access_token = created_user3.token_pair.access_token.clone();

        let other_user_id = InputUserId {
            user_id: created_user2.user.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        let request_id = created_buddy_requests[0].id;

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/user/retract_buddy_request?buddy_request_id={}",
                created_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/user/retract_buddy_request?buddy_request_id={}",
                created_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/user/retract_buddy_request?buddy_request_id={}",
                created_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.user.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 0);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/accept_buddy_request?buddy_request_id={}",
                request_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get?user_id={}&get_buddy_profile=true",
                created_user1.user.id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        serde_json::from_str::<OutputUserForBuddies>(resp_body.as_str()).unwrap_err();
    }

    #[actix_rt::test]
    async fn test_get_all_pending_buddy_requests_for_user() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1 = create_user_and_sign_in().await;
        let created_user2 = create_user_and_sign_in().await;
        let created_user3 = create_user_and_sign_in().await;

        let user1_access_token = created_user1.token_pair.access_token.clone();
        let user2_access_token = created_user2.token_pair.access_token.clone();
        let user3_access_token = created_user3.token_pair.access_token.clone();

        let other_user_id = InputUserId {
            user_id: created_user3.user.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&other_user_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user3.user.id))
            .load::<BuddyRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 2);

        // Make sure none are returned for user2 since user2 sent an invite but did not
        // receive one
        let req = test::TestRequest::get()
            .uri("/api/user/get_all_pending_buddy_requests_for_user")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddy_requests =
            serde_json::from_str::<Vec<BuddyRequest>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddy_requests.len(), 0);

        let req = test::TestRequest::get()
            .uri("/api/user/get_all_pending_buddy_requests_for_user")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddy_requests =
            serde_json::from_str::<Vec<BuddyRequest>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddy_requests.len(), 2);

        assert_eq!(
            found_buddy_requests[0].recipient_user_id,
            created_user3.user.id
        );
        assert_eq!(
            found_buddy_requests[0].sender_user_id,
            created_user1.user.id
        );
        assert!(!found_buddy_requests[0].accepted);
        assert!(found_buddy_requests[0]
            .accepted_declined_timestamp
            .is_none());

        assert_eq!(
            found_buddy_requests[1].recipient_user_id,
            created_user3.user.id
        );
        assert_eq!(
            found_buddy_requests[1].sender_user_id,
            created_user2.user.id
        );
        assert!(!found_buddy_requests[1].accepted);
        assert!(found_buddy_requests[1]
            .accepted_declined_timestamp
            .is_none());

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/user/retract_buddy_request?buddy_request_id={}",
                found_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri("/api/user/get_all_pending_buddy_requests_for_user")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddy_requests =
            serde_json::from_str::<Vec<BuddyRequest>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddy_requests.len(), 1);

        assert_eq!(
            found_buddy_requests[0].recipient_user_id,
            created_user3.user.id
        );
        assert_eq!(
            found_buddy_requests[0].sender_user_id,
            created_user2.user.id
        );
        assert!(!found_buddy_requests[0].accepted);
        assert!(found_buddy_requests[0]
            .accepted_declined_timestamp
            .is_none());

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/user/accept_buddy_request?buddy_request_id={}",
                found_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri("/api/user/get_all_pending_buddy_requests_for_user")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddy_requests =
            serde_json::from_str::<Vec<BuddyRequest>>(resp_body.as_str()).unwrap();

        assert!(found_buddy_requests.is_empty());
    }

    #[actix_rt::test]
    async fn test_get_all_invitations_made_by_user() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1 = create_user_and_sign_in().await;
        let created_user2 = create_user_and_sign_in().await;
        let created_user3 = create_user_and_sign_in().await;

        let user1_access_token = created_user1.token_pair.access_token.clone();
        let user2_access_token = created_user2.token_pair.access_token.clone();
        let user3_access_token = created_user3.token_pair.access_token.clone();

        let other_user2_id = InputUserId {
            user_id: created_user2.user.id,
        };

        let other_user3_id = InputUserId {
            user_id: created_user3.user.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user2_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user3_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .load::<BuddyRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 2);

        // Make sure none are returned for user2 since user2 received an invite but did not
        // send one
        let req = test::TestRequest::get()
            .uri("/api/user/get_all_pending_buddy_requests_made_by_user")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddy_requests =
            serde_json::from_str::<Vec<BuddyRequest>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddy_requests.len(), 0);

        let req = test::TestRequest::get()
            .uri("/api/user/get_all_pending_buddy_requests_made_by_user")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddy_requests =
            serde_json::from_str::<Vec<BuddyRequest>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddy_requests.len(), 2);

        assert_eq!(
            found_buddy_requests[0].recipient_user_id,
            created_user2.user.id
        );
        assert_eq!(
            found_buddy_requests[0].sender_user_id,
            created_user1.user.id
        );
        assert!(!found_buddy_requests[0].accepted);
        assert!(found_buddy_requests[0]
            .accepted_declined_timestamp
            .is_none());

        assert_eq!(
            found_buddy_requests[1].recipient_user_id,
            created_user3.user.id
        );
        assert_eq!(
            found_buddy_requests[1].sender_user_id,
            created_user1.user.id
        );
        assert!(!found_buddy_requests[1].accepted);
        assert!(found_buddy_requests[1]
            .accepted_declined_timestamp
            .is_none());

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/user/retract_buddy_request?buddy_request_id={}",
                found_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri("/api/user/get_all_pending_buddy_requests_made_by_user")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddy_requests =
            serde_json::from_str::<Vec<BuddyRequest>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddy_requests.len(), 1);

        assert_eq!(
            found_buddy_requests[0].recipient_user_id,
            created_user3.user.id
        );
        assert_eq!(
            found_buddy_requests[0].sender_user_id,
            created_user1.user.id
        );
        assert!(!found_buddy_requests[0].accepted);
        assert!(found_buddy_requests[0]
            .accepted_declined_timestamp
            .is_none());

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/user/accept_buddy_request?buddy_request_id={}",
                found_buddy_requests[0].id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri("/api/user/get_all_pending_buddy_requests_made_by_user")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddy_requests =
            serde_json::from_str::<Vec<BuddyRequest>>(resp_body.as_str()).unwrap();

        assert!(found_buddy_requests.is_empty());
    }

    #[actix_rt::test]
    async fn test_get_buddy_request() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1 = create_user_and_sign_in().await;
        let created_user2 = create_user_and_sign_in().await;
        let created_user3 = create_user_and_sign_in().await;

        let user1_access_token = created_user1.token_pair.access_token.clone();
        let user2_access_token = created_user2.token_pair.access_token.clone();
        let user3_access_token = created_user3.token_pair.access_token.clone();

        let other_user2_id = InputUserId {
            user_id: created_user2.user.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user2_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_request = buddy_requests
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .first::<BuddyRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get_buddy_request?buddy_request_id={}",
                created_buddy_request.id.clone()
            ))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddy_request = serde_json::from_str::<BuddyRequest>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddy_request.recipient_user_id, created_user2.user.id);
        assert_eq!(found_buddy_request.sender_user_id, created_user1.user.id);
        assert!(!found_buddy_request.accepted);
        assert!(found_buddy_request.accepted_declined_timestamp.is_none());

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get_buddy_request?buddy_request_id={}",
                created_buddy_request.id.clone()
            ))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        assert_eq!(found_buddy_request.recipient_user_id, created_user2.user.id);
        assert_eq!(found_buddy_request.sender_user_id, created_user1.user.id);
        assert!(!found_buddy_request.accepted);
        assert!(found_buddy_request.accepted_declined_timestamp.is_none());

        // Test can't get for another user
        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/user/get_buddy_request?buddy_request_id={}",
                created_buddy_request.id
            ))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    }

    #[actix_rt::test]
    async fn test_delete_buddy_relationship() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1 = create_user_and_sign_in().await;
        let created_user2 = create_user_and_sign_in().await;
        let created_user3 = create_user_and_sign_in().await;

        let user1_access_token = created_user1.token_pair.access_token.clone();
        let user2_access_token = created_user2.token_pair.access_token.clone();
        let user3_access_token = created_user3.token_pair.access_token.clone();

        let other_user2_id = InputUserId {
            user_id: created_user2.user.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user2_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_request = buddy_requests
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .first::<BuddyRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/user/accept_buddy_request?buddy_request_id={}",
                created_buddy_request.id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddies.len(), 1);
        assert_eq!(found_buddies[0].id, created_user2.user.id);

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddies.len(), 1);
        assert_eq!(found_buddies[0].id, created_user1.user.id);

        // Test another user can't delete relationship
        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/user/delete_buddy_relationship?user_id={}",
                created_user1.user.id
            ))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/user/delete_buddy_relationship?user_id={}",
                created_user2.user.id
            ))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/user/delete_buddy_relationship?user_id={}",
                created_user1.user.id
            ))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddies.len(), 0);

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert!(found_buddies.is_empty());

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user2_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_request = buddy_requests
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .first::<BuddyRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/user/accept_buddy_request?buddy_request_id={}",
                created_buddy_request.id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddies.len(), 1);
        assert_eq!(found_buddies[0].id, created_user2.user.id);

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddies.len(), 1);
        assert_eq!(found_buddies[0].id, created_user1.user.id);

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/user/delete_buddy_relationship?user_id={}",
                created_user2.user.id
            ))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert!(found_buddies.is_empty());

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert!(found_buddies.is_empty());
    }

    #[actix_rt::test]
    async fn test_get_buddies() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1 = create_user_and_sign_in().await;
        let created_user2 = create_user_and_sign_in().await;
        let created_user3 = create_user_and_sign_in().await;

        let user1_access_token = created_user1.token_pair.access_token.clone();
        let user2_access_token = created_user2.token_pair.access_token.clone();
        let user3_access_token = created_user3.token_pair.access_token.clone();

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert!(found_buddies.is_empty());

        let other_user2_id = InputUserId {
            user_id: created_user2.user.id,
        };

        let other_user3_id = InputUserId {
            user_id: created_user3.user.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user2_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_request = buddy_requests
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .first::<BuddyRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/user/accept_buddy_request?buddy_request_id={}",
                created_buddy_request.id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddies.len(), 1);
        assert_eq!(found_buddies[0].id, created_user2.user.id);

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddies.len(), 1);
        assert_eq!(found_buddies[0].id, created_user1.user.id);

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user3_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let created_buddy_request = buddy_requests
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.user.id))
            .filter(buddy_request_fields::recipient_user_id.eq(created_user3.user.id))
            .first::<BuddyRequest>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/user/accept_buddy_request?buddy_request_id={}",
                created_buddy_request.id,
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddies.len(), 2);

        let found_buddies_ids = found_buddies
            .iter()
            .map(|buddy| buddy.id)
            .collect::<Vec<_>>();
        assert!(found_buddies_ids.contains(&created_user2.user.id));
        assert!(found_buddies_ids.contains(&created_user3.user.id));

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddies.len(), 1);
        assert_eq!(found_buddies[0].id, created_user1.user.id);

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddies.len(), 1);
        assert_eq!(found_buddies[0].id, created_user1.user.id);

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/user/delete_buddy_relationship?user_id={}",
                created_user1.user.id
            ))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert_eq!(found_buddies.len(), 1);
        assert_eq!(found_buddies[0].id, created_user3.user.id);

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/user/delete_buddy_relationship?user_id={}",
                created_user1.user.id
            ))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri("/api/user/get_buddies")
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let found_buddies = serde_json::from_str::<Vec<User>>(resp_body.as_str()).unwrap();

        assert!(found_buddies.is_empty());
    }
}
