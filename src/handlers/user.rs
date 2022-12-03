use actix_web::{web, HttpResponse};
use log::error;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::definitions::DbThreadPool;
use crate::env;
use crate::handlers::error::ServerError;
use crate::handlers::request_io::{
    CurrentAndNewPasswordPair, InputBuddyRequestId, InputEditUser, InputOptionalUserId, InputUser,
    InputUserId, OutputUserForBuddies, OutputUserPrivate, OutputUserPublic, SigninToken,
};
use crate::middleware;
use crate::utils::db;
use crate::utils::{auth_token, otp, password_hasher, validators};

// TODO: Test when query param is some
pub async fn get(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    input_user_id: web::Query<InputOptionalUserId>,
) -> Result<HttpResponse, ServerError> {
    let is_another_user_requesting = input_user_id.user_id.is_some();

    let user_id = if is_another_user_requesting {
        input_user_id.user_id.unwrap()
    } else {
        auth_user_claims.0.uid
    };

    let mut db_connection = db_thread_pool
        .get()
        .expect("Failed to access database thread pool");
    let mut db_connection2 = db_thread_pool
        .get()
        .expect("Failed to access database thread pool");

    let user =
        match web::block(move || db::user::get_user_by_id(&mut db_connection, user_id)).await? {
            Ok(u) => u,
            Err(e) => match e {
                diesel::result::Error::InvalidCString(_)
                | diesel::result::Error::DeserializationError(_) => {
                    return Err(ServerError::InvalidFormat(None))
                }
                diesel::result::Error::NotFound => {
                    return Err(ServerError::AccessForbidden(Some("No user with ID")))
                }
                _ => {
                    error!("{}", e);
                    return Err(ServerError::DatabaseTransactionError(Some(
                        "Failed to get user data",
                    )));
                }
            },
        };

    if is_another_user_requesting && user_id != auth_user_claims.0.uid {
        let mut are_buddies = false;

        if input_user_id.is_buddy.is_some() && input_user_id.is_buddy.unwrap() {
            are_buddies = match web::block(move || {
                db::user::check_are_buddies(
                    &mut db_connection2,
                    input_user_id.user_id.unwrap(),
                    auth_user_claims.0.uid,
                )
            })
            .await?
            {
                Ok(buddies) => buddies,
                Err(e) => {
                    error!("{}", e);
                    return Err(ServerError::DatabaseTransactionError(Some(
                        "Failed to get user data",
                    )));
                }
            };
        }

        if !are_buddies {
            let output_user = OutputUserPublic {
                id: user.id,
                is_premium: user.is_premium,
                is_active: user.is_active,
                first_name: user.first_name,
                last_name: user.last_name,
                currency: user.currency,
            };

            return Ok(HttpResponse::Ok().json(output_user));
        }
    }

    if is_another_user_requesting {
        let output_user = OutputUserForBuddies {
            id: user.id,
            is_active: user.is_active,
            is_premium: user.is_premium,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            currency: user.currency,
        };

        return Ok(HttpResponse::Ok().json(output_user));
    }

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

    Ok(HttpResponse::Ok().json(output_user))
}

// TODO: Get another user by email

pub async fn create(
    db_thread_pool: web::Data<DbThreadPool>,
    user_data: web::Json<InputUser>,
) -> Result<HttpResponse, ServerError> {
    if !user_data.0.validate_email_address().is_valid() {
        return Err(ServerError::InvalidFormat(Some("Invalid email address")));
    }

    if let validators::Validity::Invalid(msg) = user_data.0.validate_strong_password() {
        return Err(ServerError::InputRejected(Some(msg)));
    }

    let user = match web::block(move || {
        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::create_user(&mut db_connection, &user_data)
    })
    .await?
    {
        Ok(u) => u,
        Err(e) => match e {
            diesel::result::Error::InvalidCString(_)
            | diesel::result::Error::DeserializationError(_) => {
                return Err(ServerError::InvalidFormat(None))
            }
            diesel::result::Error::NotFound => {
                return Err(ServerError::AccessForbidden(Some("No user with ID")))
            }
            diesel::result::Error::DatabaseError(error_kind, _) => match error_kind {
                diesel::result::DatabaseErrorKind::UniqueViolation => {
                    return Err(ServerError::AlreadyExists(Some(
                        "A user with the given email address already exists",
                    )))
                }
                _ => {
                    error!("{}", e);
                    return Err(ServerError::InternalError(Some("Failed to create user")));
                }
            },
            _ => {
                error!("{}", e);
                return Err(ServerError::InternalError(Some("Failed to create user")));
            }
        },
    };

    let signin_token = auth_token::generate_signin_token(auth_token::TokenParams {
        user_id: &user.id,
        user_email: &user.email,
        user_currency: &user.currency,
    });

    let signin_token = match signin_token {
        Ok(signin_token) => signin_token,
        Err(e) => {
            error!("{}", e);
            return Err(ServerError::InternalError(Some(
                "Failed to generate sign-in token for user",
            )));
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
    ) {
        Ok(p) => p,
        Err(e) => {
            error!("{}", e);
            return Err(ServerError::InternalError(Some("Failed to generate OTP")));
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
        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::edit_user(&mut db_connection, auth_user_claims.0.uid, &user_data)
    })
    .await
    .map(|_| HttpResponse::Ok().finish())
    .map_err(|e| {
        error!("{}", e);
        ServerError::DatabaseTransactionError(Some("Failed to edit user"))
    })
}

pub async fn change_password(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    password_pair: web::Json<CurrentAndNewPasswordPair>,
) -> Result<HttpResponse, ServerError> {
    let db_thread_pool_pointer_copy = db_thread_pool.clone();

    let user = match web::block(move || {
        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::get_user_by_id(&mut db_connection, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(u) => u,
        Err(e) => {
            error!("{}", e);
            return Err(ServerError::InputRejected(Some("User not found")));
        }
    };

    let current_password = password_pair.current_password.clone();

    let does_password_match_hash =
        web::block(move || password_hasher::verify_hash(&current_password, &user.password_hash))
            .await?;

    if !does_password_match_hash {
        return Err(ServerError::UserUnauthorized(Some(
            "Current password was incorrect",
        )));
    }

    let new_password_validity = validators::validate_strong_password(
        &password_pair.new_password,
        &user.email,
        &user.first_name,
        &user.last_name,
        &user.date_of_birth,
    );

    if let validators::Validity::Invalid(msg) = new_password_validity {
        return Err(ServerError::InputRejected(Some(msg)));
    };

    web::block(move || {
        let mut db_connection = db_thread_pool_pointer_copy
            .get()
            .expect("Failed to access database thread pool");

        db::user::change_password(
            &mut db_connection,
            auth_user_claims.0.uid,
            &password_pair.new_password,
        )
    })
    .await
    .map(|_| HttpResponse::Ok().finish())
    .map_err(|e| {
        error!("{}", e);
        ServerError::DatabaseTransactionError(Some("Failed to update password"))
    })
}

// TODO: Test
pub async fn send_buddy_request(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    other_user_id: web::Json<InputUserId>,
) -> Result<HttpResponse, ServerError> {
    if other_user_id.user_id == auth_user_claims.0.uid {
        return Err(ServerError::InputRejected(Some(
            "Requester and recipient have the same ID",
        )));
    }

    match web::block(move || {
        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::send_buddy_request(
            &mut db_connection,
            other_user_id.user_id,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            diesel::result::Error::InvalidCString(_)
            | diesel::result::Error::DeserializationError(_) => {
                return Err(ServerError::InvalidFormat(None));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to create buddy request",
                )));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

// TODO: Test
pub async fn retract_buddy_request(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    request_id: web::Query<InputBuddyRequestId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::delete_buddy_request(
            &mut db_connection,
            request_id.buddy_request_id,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(count) => {
            if count == 0 {
                return Err(ServerError::NotFound(Some(
                    "No buddy request with provided ID was made by user",
                )));
            }
        }
        Err(e) => match e {
            diesel::result::Error::NotFound => {
                return Err(ServerError::NotFound(Some(
                    "No buddy request with provided ID",
                )));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to delete request",
                )));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

// TODO: Test
pub async fn accept_buddy_request(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    request_id: web::Query<InputBuddyRequestId>,
) -> Result<HttpResponse, ServerError> {
    let db_thread_pool_ref = db_thread_pool.clone();
    let request_id = request_id.buddy_request_id;

    let buddy_request_data = match web::block(move || {
        let mut db_connection = db_thread_pool_ref
            .get()
            .expect("Failed to access database thread pool");

        db::user::mark_buddy_request_accepted(
            &mut db_connection,
            request_id,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(req_data) => req_data,
        Err(e) => match e {
            diesel::result::Error::NotFound => {
                return Err(ServerError::NotFound(Some(
                    "No buddy request with provided ID",
                )));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to accept buddy request",
                )));
            }
        },
    };

    match web::block(move || {
        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::create_buddy_relationship(
            &mut db_connection,
            buddy_request_data.sender_user_id,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => {
            error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(
                "Failed to accept buddy request",
            )));
        }
    }

    Ok(HttpResponse::Ok().finish())
}

// TODO: Test
pub async fn decline_buddy_request(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    request_id: web::Query<InputBuddyRequestId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::mark_buddy_request_declined(
            &mut db_connection,
            request_id.buddy_request_id,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(count) => {
            if count == 0 {
                return Err(ServerError::NotFound(Some(
                    "No buddy request with provided ID",
                )));
            }
        }
        Err(e) => match e {
            diesel::result::Error::NotFound => {
                return Err(ServerError::NotFound(Some(
                    "No buddy request with provided ID",
                )));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to decline buddy request",
                )));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

// TODO: Test
pub async fn get_all_pending_buddy_requests_for_user(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let requests = match web::block(move || {
        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::get_all_pending_buddy_requests_for_user(
            &mut db_connection,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(reqs) => reqs,
        Err(e) => match e {
            diesel::result::Error::NotFound => {
                return Err(ServerError::NotFound(Some("No buddy requests for user")));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to find buddy requests",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().json(requests))
}

// TODO: Test
pub async fn get_all_pending_buddy_requests_made_by_user(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let requests = match web::block(move || {
        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::get_all_pending_buddy_requests_made_by_user(
            &mut db_connection,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(reqs) => reqs,
        Err(e) => match e {
            diesel::result::Error::NotFound => {
                return Err(ServerError::NotFound(Some(
                    "No buddy requests made by user",
                )));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to find buddy requests",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().json(requests))
}

// TODO: Test
pub async fn get_buddy_request(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    request_id: web::Query<InputBuddyRequestId>,
) -> Result<HttpResponse, ServerError> {
    let request = match web::block(move || {
        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::get_buddy_request(
            &mut db_connection,
            request_id.buddy_request_id,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(req) => req,
        Err(e) => match e {
            diesel::result::Error::NotFound => {
                return Err(ServerError::NotFound(Some("Buddy request not found")));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to find buddy request",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().json(request))
}

// TODO: Test
pub async fn delete_buddy_relationship(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    other_user_id: web::Query<InputUserId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::delete_buddy_relationship(
            &mut db_connection,
            auth_user_claims.0.uid,
            other_user_id.user_id,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            diesel::result::Error::NotFound => {
                return Err(ServerError::NotFound(Some("Buddy relationship not found")));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to delete buddy relationship",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

// TODO: Test
pub async fn get_buddies(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let buddies = match web::block(move || {
        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::get_buddies(&mut db_connection, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => {
            error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(
                "Failed to find buddies for user",
            )));
        }
    };

    Ok(HttpResponse::Ok().json(buddies))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use actix_web::web::Data;
    use actix_web::{http, test, App};
    use chrono::NaiveDate;
    use diesel::prelude::*;
    use rand::prelude::*;

    use crate::env;
    use crate::handlers::request_io::{SigninTokenOtpPair, TokenPair};
    use crate::models::buddy_relationship::BuddyRelationship;
    use crate::models::buddy_request::BuddyRequest;
    use crate::models::user::User;
    use crate::schema::buddy_relationships as buddy_relationship_fields;
    use crate::schema::buddy_relationships::dsl::buddy_relationships;
    use crate::schema::buddy_requests as buddy_request_fields;
    use crate::schema::buddy_requests::dsl::buddy_requests;
    use crate::schema::users as user_fields;
    use crate::schema::users::dsl::users;
    use crate::services;
    use crate::utils::auth_token::TokenClaims;

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
            date_of_birth: NaiveDate::from_ymd_opt(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            )
            .unwrap(),
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

        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();
        let user = db::user::get_user_by_id(&mut db_connection, user_id).unwrap();

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(user_id, current_time).unwrap();

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
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd_opt(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            )
            .unwrap(),
            currency: String::from("USD"),
        };

        let req = test::TestRequest::post()
            .uri("/api/user/create")
            .insert_header(("content-type", "application/json"))
            .set_json(&new_user)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::CREATED);

        let mut db_connection = db_thread_pool.get().unwrap();

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
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("1dIbCx^n@VF9f&0*c*39"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd_opt(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            )
            .unwrap(),
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
        let otp = otp::generate_otp(user_id, current_time).unwrap();

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
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user = InputUser {
            email: format!("test_user{}test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd_opt(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            )
            .unwrap(),
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
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("Password1234"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd_opt(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            )
            .unwrap(),
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
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("1dIbCx^n@VF9f&0*c*39"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd_opt(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            )
            .unwrap(),
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
        let otp = otp::generate_otp(user_id, current_time).unwrap();

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
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("1dIbCx^n@VF9f&0*c*39"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd_opt(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            )
            .unwrap(),
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
        let otp = otp::generate_otp(user_id, current_time).unwrap();

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
            .uri(&format!("/api/user/get?user_id={}&is_buddy=true", user_id))
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
            .uri(&format!("/api/user/get?user_id={}&is_buddy=false", user_id))
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
            .uri(&format!("/api/user/get?user_id={}&is_buddy=true", user_id))
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
                "/api/user/get?user_id={}&is_buddy=true",
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
    async fn test_change_password() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("tNmUV%9$khHK2TqOLw*%W"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd_opt(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            )
            .unwrap(),
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
        let otp = otp::generate_otp(user_id, current_time).unwrap();

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

        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        let db_password_hash = db::user::get_user_by_id(&mut db_connection, user_id)
            .unwrap()
            .password_hash;

        assert!(!password_hasher::verify_hash(
            &new_user.password,
            &db_password_hash
        ));
        assert!(password_hasher::verify_hash(
            &password_pair.new_password,
            &db_password_hash
        ));
    }

    #[actix_rt::test]
    async fn test_change_password_current_password_wrong() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("tNmUV%9$khHK2TqOLw*%W"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd_opt(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            )
            .unwrap(),
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
        let otp = otp::generate_otp(user_id, current_time).unwrap();

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

        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        let db_password_hash = db::user::get_user_by_id(&mut db_connection, user_id)
            .unwrap()
            .password_hash;

        assert!(password_hasher::verify_hash(
            &new_user.password,
            &db_password_hash
        ));
        assert!(!password_hasher::verify_hash(
            &password_pair.new_password,
            &db_password_hash
        ));
    }

    #[actix_rt::test]
    async fn test_change_password_new_password_invalid() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("tNmUV%9$khHK2TqOLw*%W"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd_opt(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            )
            .unwrap(),
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
        let otp = otp::generate_otp(user_id, current_time).unwrap();

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

        let mut db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        let db_password_hash = db::user::get_user_by_id(&mut db_connection, user_id)
            .unwrap()
            .password_hash;

        assert!(password_hasher::verify_hash(
            &new_user.password,
            &db_password_hash
        ));
        assert!(!password_hasher::verify_hash(
            &password_pair.new_password,
            &db_password_hash
        ));
    }

    #[actix_rt::test]
    async fn test_send_buddy_request_and_accept() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let mut db_connection = db_thread_pool.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
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

        let instant_before_request = chrono::Utc::now().naive_utc();

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let instant_after_request = chrono::Utc::now().naive_utc();

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
                "/api/user/get?user_id={}&is_buddy=true",
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
                "/api/user/get?user_id={}&is_buddy=true",
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
    }

    #[actix_rt::test]
    async fn test_cannot_accept_buddy_requests_for_another_user() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let mut db_connection = db_thread_pool.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
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
                "/api/user/get?user_id={}&is_buddy=true",
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
                "/api/user/get?user_id={}&is_buddy=true",
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
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let mut db_connection = db_thread_pool.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
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

        let instant_before_request = chrono::Utc::now().naive_utc();

        let req = test::TestRequest::post()
            .uri("/api/user/send_buddy_request")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&other_user_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let instant_after_request = chrono::Utc::now().naive_utc();

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
                "/api/user/get?user_id={}&is_buddy=true",
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
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let mut db_connection = db_thread_pool.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
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
                "/api/user/get?user_id={}&is_buddy=true",
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
                "/api/user/get?user_id={}&is_buddy=true",
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
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let mut db_connection = db_thread_pool.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
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
                "/api/user/get?user_id={}&is_buddy=true",
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
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let mut db_connection = db_thread_pool.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
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
                "/api/user/get?user_id={}&is_buddy=true",
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

    // #[actix_rt::test]
    // async fn test_get_all_pending_buddy_requests_for_user() {
    //     let db_thread_pool = &*env::testing::DB_THREAD_POOL;
    //     let mut db_connection = db_thread_pool.get().unwrap();

    //     let app = test::init_service(
    //         App::new()
    //             .app_data(Data::new(db_thread_pool.clone()))
    //             .configure(services::api::configure),
    //     )
    //     .await;

    //     let created_user1 = create_user_and_sign_in().await;
    //     let created_user2 = create_user_and_sign_in().await;
    //     let created_user3 = create_user_and_sign_in().await;

    //     let user1_access_token = created_user1.token_pair.access_token.clone();
    //     let user2_access_token = created_user2.token_pair.access_token.clone();
    //     let user3_access_token = created_user3.token_pair.access_token.clone();

    //     let other_user_id = InputUserId {
    //         user_id: created_user3.user.id.clone(),
    //     };

    //     let req = test::TestRequest::post()
    //         .uri("/api/user/send_buddy_request")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .set_json(&other_user_id)
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let req = test::TestRequest::post()
    //         .uri("/api/user/send_buddy_request")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user2_access_token}")))
    //         .set_json(&other_user_id)
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let created_buddy_requests = buddy_requests
    //         .filter(buddy_request_fields::recipient_user_id.eq(created_user3.user.id))
    //         .load::<BuddyRequest>(&mut db_connection)
    //         .unwrap();

    //     assert_eq!(created_buddy_requests.len(), 2);

    //     let req = test::TestRequest::get()
    //         .uri("/api/user/get_all_pending_buddy_requests_for_user")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user3_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
    //     let found_buddy_requests =
    //         serde_json::from_str::<Vec<BuddyRequest>>(resp_body.as_str()).unwrap();

    //     assert_eq!(found_buddy_requests.len(), 2);

    // assert_eq!(found_buddy_requests[0]

    // let created_user1_budget2 =
    //     serde_json::from_str::<OutputBudget>(create_budget_resp_body.as_str()).unwrap();

    // let invitation_info_budget1 = UserInvitationToBudget {
    //     invitee_user_id: created_user2_id,
    //     budget_id: created_user1_budget1.id,
    // };

    // let invitation_info_budget2 = UserInvitationToBudget {
    //     invitee_user_id: created_user2_id,
    //     budget_id: created_user1_budget2.id,
    // };

    // let req = test::TestRequest::post()
    //     .uri("/api/budget/invite")
    //     .insert_header(("content-type", "application/json"))
    //     .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //     .set_json(&invitation_info_budget1)
    //     .to_request();

    // let resp = test::call_service(&app, req).await;
    // assert_eq!(resp.status(), http::StatusCode::OK);

    // let req = test::TestRequest::post()
    //     .uri("/api/budget/invite")
    //     .insert_header(("content-type", "application/json"))
    //     .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //     .set_json(&invitation_info_budget2)
    //     .to_request();

    // let resp = test::call_service(&app, req).await;
    // assert_eq!(resp.status(), http::StatusCode::OK);

    // let req = test::TestRequest::get()
    //     .uri("/api/budget/get_all_pending_invitations_for_user")
    //     .insert_header(("content-type", "application/json"))
    //     .insert_header(("authorization", format!("bearer {user2_access_token}")))
    //     .to_request();

    // let resp = test::call_service(&app, req).await;
    // assert_eq!(resp.status(), http::StatusCode::OK);

    // let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
    // let invitations =
    //     serde_json::from_str::<Vec<BudgetShareEvent>>(resp_body.as_str()).unwrap();

    // assert_eq!(invitations.len(), 2);

    // let budget1_invitation = &invitations[0];
    // let budget2_invitation = &invitations[1];

    // assert_eq!(budget1_invitation.recipient_user_id, created_user2_id);
    // assert_eq!(budget1_invitation.sender_user_id, created_user1_id);
    // assert_eq!(budget1_invitation.budget_id, created_user1_budget1.id);
    // assert_eq!(budget1_invitation.accepted, false);
    // assert!(budget1_invitation.accepted_declined_timestamp.is_none());

    // assert_eq!(budget2_invitation.recipient_user_id, created_user2_id);
    // assert_eq!(budget2_invitation.sender_user_id, created_user1_id);
    // assert_eq!(budget2_invitation.budget_id, created_user1_budget2.id);
    // assert_eq!(budget2_invitation.accepted, false);
    // assert!(budget2_invitation.accepted_declined_timestamp.is_none());
    // }

    // TODO

    // #[actix_rt::test]
    // async fn test_get_all_invitations_made_by_user() {
    //     let db_thread_pool = &*env::testing::DB_THREAD_POOL;

    //     let app = test::init_service(
    //         App::new()
    //             .app_data(Data::new(db_thread_pool.clone()))
    //             .configure(services::api::configure),
    //     )
    //     .await;

    //     let created_user1_and_budget =
    //         create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
    //     let created_user1_budget1 = created_user1_and_budget.budget;
    //     let created_user1_id = created_user1_and_budget.user_id;

    //     let created_user2_and_budget =
    //         create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
    //     let created_user2_id = created_user2_and_budget.user_id;

    //     let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();

    //     let category0 = InputCategory {
    //         id: 0,
    //         name: format!("First Random Category for user1_budget2"),
    //         limit_cents: rand::thread_rng().gen_range(100..500),
    //         color: String::from("#ff11ee"),
    //     };

    //     let category1 = InputCategory {
    //         id: 1,
    //         name: format!("Second Random Category user1_budget2"),
    //         limit_cents: rand::thread_rng().gen_range(100..500),
    //         color: String::from("#112233"),
    //     };

    //     let budget_categories = vec![category0, category1];

    //     let new_budget = InputBudget {
    //         name: format!("Test Budget #2"),
    //         description: Some(format!("This is a description of Test Budget #2.",)),
    //         categories: budget_categories.clone(),
    //         start_date: NaiveDate::from_ymd_opt(
    //             2021,
    //             rand::thread_rng().gen_range(1..=12),
    //             rand::thread_rng().gen_range(1..=28),
    //         ),
    //         end_date: NaiveDate::from_ymd(
    //             2023,
    //             rand::thread_rng().gen_range(1..=12),
    //             rand::thread_rng().gen_range(1..=28),
    //         ),
    //     };

    //     let create_budget_req = test::TestRequest::post()
    //         .uri("/api/budget/create")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .set_json(&new_budget)
    //         .to_request();

    //     let create_budget_resp = test::call_service(&app, create_budget_req).await;
    //     let create_budget_resp_body = String::from_utf8(
    //         actix_web::test::read_body(create_budget_resp)
    //             .await
    //             .to_vec(),
    //     )
    //     .unwrap();

    //     let created_user1_budget2 =
    //         serde_json::from_str::<OutputBudget>(create_budget_resp_body.as_str()).unwrap();

    //     let invitation_info_budget1 = UserInvitationToBudget {
    //         invitee_user_id: created_user2_id,
    //         budget_id: created_user1_budget1.id,
    //     };

    //     let invitation_info_budget2 = UserInvitationToBudget {
    //         invitee_user_id: created_user2_id,
    //         budget_id: created_user1_budget2.id,
    //     };

    //     let req = test::TestRequest::post()
    //         .uri("/api/budget/invite")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .set_json(&invitation_info_budget1)
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let req = test::TestRequest::post()
    //         .uri("/api/budget/invite")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .set_json(&invitation_info_budget2)
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let req = test::TestRequest::get()
    //         .uri("/api/budget/get_all_pending_invitations_made_by_user")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
    //     let invitations =
    //         serde_json::from_str::<Vec<BudgetShareEvent>>(resp_body.as_str()).unwrap();

    //     assert_eq!(invitations.len(), 2);

    //     let budget1_invitation = &invitations[0];
    //     let budget2_invitation = &invitations[1];

    //     assert_eq!(budget1_invitation.recipient_user_id, created_user2_id);
    //     assert_eq!(budget1_invitation.sender_user_id, created_user1_id);
    //     assert_eq!(budget1_invitation.budget_id, created_user1_budget1.id);
    //     assert_eq!(budget1_invitation.accepted, false);
    //     assert!(budget1_invitation.accepted_declined_timestamp.is_none());

    //     assert_eq!(budget2_invitation.recipient_user_id, created_user2_id);
    //     assert_eq!(budget2_invitation.sender_user_id, created_user1_id);
    //     assert_eq!(budget2_invitation.budget_id, created_user1_budget2.id);
    //     assert_eq!(budget2_invitation.accepted, false);
    //     assert!(budget2_invitation.accepted_declined_timestamp.is_none());
    // }

    // #[actix_rt::test]
    // async fn test_get_invitation() {
    //     let db_thread_pool = &*env::testing::DB_THREAD_POOL;
    //     let mut db_connection = db_thread_pool.get().unwrap();

    //     let app = test::init_service(
    //         App::new()
    //             .app_data(Data::new(db_thread_pool.clone()))
    //             .configure(services::api::configure),
    //     )
    //     .await;

    //     let created_user1_and_budget =
    //         create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
    //     let created_user1_budget = created_user1_and_budget.budget;
    //     let created_user1_id = created_user1_and_budget.user_id;

    //     let created_user2_and_budget =
    //         create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
    //     let created_user2_id = created_user2_and_budget.user_id;

    //     let created_user3_and_budget =
    //         create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;

    //     let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
    //     let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();
    //     let user3_access_token = created_user3_and_budget.token_pair.access_token.clone();

    //     let invitation_info_budget = UserInvitationToBudget {
    //         invitee_user_id: created_user2_id,
    //         budget_id: created_user1_budget.id,
    //     };

    //     let instant_before_share = chrono::Utc::now().naive_utc();

    //     let req = test::TestRequest::post()
    //         .uri("/api/budget/invite")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .set_json(&invitation_info_budget)
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let instant_after_share = chrono::Utc::now().naive_utc();

    //     let share_events = budget_share_events
    //         .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
    //         .load::<BudgetShareEvent>(&mut db_connection)
    //         .unwrap();

    //     assert_eq!(share_events.len(), 1);

    //     let invite_id = InputShareEventId {
    //         share_event_id: share_events[0].id,
    //     };

    //     let req = test::TestRequest::get()
    //         .uri(&format!(
    //             "/api/budget/get_invitation?share_event_id={}",
    //             invite_id.share_event_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
    //     let invitation = serde_json::from_str::<BudgetShareEvent>(resp_body.as_str()).unwrap();

    //     assert_eq!(invitation.recipient_user_id, created_user2_id);
    //     assert_eq!(invitation.sender_user_id, created_user1_id);
    //     assert_eq!(invitation.accepted, false);

    //     assert!(invitation.accepted_declined_timestamp.is_none());
    //     assert!(invitation.created_timestamp > instant_before_share);
    //     assert!(invitation.created_timestamp < instant_after_share);

    //     let req = test::TestRequest::get()
    //         .uri(&format!(
    //             "/api/budget/get_invitation?share_event_id={}",
    //             invite_id.share_event_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user2_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
    //     let invitation = serde_json::from_str::<BudgetShareEvent>(resp_body.as_str()).unwrap();

    //     assert_eq!(invitation.recipient_user_id, created_user2_id);
    //     assert_eq!(invitation.sender_user_id, created_user1_id);
    //     assert_eq!(invitation.accepted, false);

    //     assert!(invitation.accepted_declined_timestamp.is_none());
    //     assert!(invitation.created_timestamp > instant_before_share);
    //     assert!(invitation.created_timestamp < instant_after_share);

    //     let req = test::TestRequest::get()
    //         .uri(&format!(
    //             "/api/budget/get_invitation?share_event_id={}",
    //             invite_id.share_event_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user3_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    // }

    // #[actix_rt::test]
    // async fn test_remove_user() {
    //     let db_thread_pool = &*env::testing::DB_THREAD_POOL;
    //     let mut db_connection = db_thread_pool.get().unwrap();

    //     let app = test::init_service(
    //         App::new()
    //             .app_data(Data::new(db_thread_pool.clone()))
    //             .configure(services::api::configure),
    //     )
    //     .await;

    //     let created_user1_and_budget =
    //         create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
    //     let created_user1_budget = created_user1_and_budget.budget;
    //     let created_user1_id = created_user1_and_budget.user_id;

    //     let created_user2_and_budget =
    //         create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
    //     let created_user2_id = created_user2_and_budget.user_id;

    //     let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
    //     let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();

    //     let invitation_info_budget = UserInvitationToBudget {
    //         invitee_user_id: created_user2_id,
    //         budget_id: created_user1_budget.id,
    //     };

    //     let req = test::TestRequest::post()
    //         .uri("/api/budget/invite")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .set_json(&invitation_info_budget)
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let share_events = budget_share_events
    //         .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
    //         .load::<BudgetShareEvent>(&mut db_connection)
    //         .unwrap();

    //     assert_eq!(share_events.len(), 1);

    //     let invite_id = InputShareEventId {
    //         share_event_id: share_events[0].id,
    //     };

    //     let req = test::TestRequest::put()
    //         .uri(&format!(
    //             "/api/budget/accept_invitation?share_event_id={}",
    //             invite_id.share_event_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user2_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let budget_association = user_budgets
    //         .filter(user_budget_fields::user_id.eq(created_user2_id))
    //         .filter(user_budget_fields::budget_id.eq(created_user1_budget.id))
    //         .first::<UserBudget>(&mut db_connection)
    //         .unwrap();

    //     assert_eq!(budget_association.user_id, created_user2_id);
    //     assert_eq!(budget_association.budget_id, created_user1_budget.id);

    //     let budget_id = InputBudgetId {
    //         budget_id: created_user1_budget.id,
    //     };

    //     let req = test::TestRequest::delete()
    //         .uri(&format!(
    //             "/api/budget/remove_budget?budget_id={}",
    //             budget_id.budget_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let share_events = budget_share_events
    //         .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
    //         .load::<BudgetShareEvent>(&mut db_connection)
    //         .unwrap();

    //     assert_eq!(share_events.len(), 1); // Share event still exists

    //     let budget_association = user_budgets
    //         .filter(user_budget_fields::user_id.eq(created_user1_id))
    //         .filter(user_budget_fields::budget_id.eq(created_user1_budget.id))
    //         .first::<UserBudget>(&mut db_connection);

    //     assert!(budget_association.is_err());

    //     let budget_association = user_budgets
    //         .filter(user_budget_fields::user_id.eq(created_user2_id))
    //         .filter(user_budget_fields::budget_id.eq(created_user1_budget.id))
    //         .first::<UserBudget>(&mut db_connection);

    //     assert!(budget_association.is_ok());

    //     let req = test::TestRequest::get()
    //         .uri(&format!(
    //             "/api/budget/get?budget_id={}",
    //             budget_id.budget_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

    //     let req = test::TestRequest::get()
    //         .uri(&format!(
    //             "/api/budget/get?budget_id={}",
    //             budget_id.budget_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user2_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);
    // }

    // #[actix_rt::test]
    // async fn test_remove_last_user_deletes_budget() {
    //     let db_thread_pool = &*env::testing::DB_THREAD_POOL;
    //     let mut db_connection = db_thread_pool.get().unwrap();

    //     let app = test::init_service(
    //         App::new()
    //             .app_data(Data::new(db_thread_pool.clone()))
    //             .configure(services::api::configure),
    //     )
    //     .await;

    //     let created_user1_and_budget =
    //         create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
    //     let created_user1_id = created_user1_and_budget.user_id;
    //     let created_user1_budget = created_user1_and_budget.budget;

    //     let created_user2_and_budget =
    //         create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
    //     let created_user2_id = created_user2_and_budget.user_id;
    //     let created_user2_budget = created_user2_and_budget.budget;

    //     let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
    //     let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();

    //     let invitation_info_budget = UserInvitationToBudget {
    //         invitee_user_id: created_user2_id,
    //         budget_id: created_user1_budget.id,
    //     };

    //     let req = test::TestRequest::post()
    //         .uri("/api/budget/invite")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .set_json(&invitation_info_budget)
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let share_events = budget_share_events
    //         .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
    //         .load::<BudgetShareEvent>(&mut db_connection)
    //         .unwrap();

    //     assert_eq!(share_events.len(), 1);

    //     let invite_id = InputShareEventId {
    //         share_event_id: share_events[0].id,
    //     };

    //     let req = test::TestRequest::put()
    //         .uri(&format!(
    //             "/api/budget/accept_invitation?share_event_id={}",
    //             invite_id.share_event_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user2_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let budget_association = user_budgets
    //         .filter(user_budget_fields::user_id.eq(created_user2_id))
    //         .filter(user_budget_fields::budget_id.eq(created_user1_budget.id))
    //         .first::<UserBudget>(&mut db_connection)
    //         .unwrap();

    //     assert_eq!(budget_association.user_id, created_user2_id);
    //     assert_eq!(budget_association.budget_id, created_user1_budget.id);

    //     let budget_id = InputBudgetId {
    //         budget_id: created_user1_budget.id,
    //     };

    //     let req = test::TestRequest::delete()
    //         .uri(&format!(
    //             "/api/budget/remove_budget?budget_id={}",
    //             budget_id.budget_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let budget = budgets
    //         .find(created_user1_budget.id)
    //         .load::<Budget>(&mut db_connection);

    //     assert!(budget.is_ok());

    //     let req = test::TestRequest::delete()
    //         .uri(&format!(
    //             "/api/budget/remove_budget?budget_id={}",
    //             budget_id.budget_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user2_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let share_events = budget_share_events
    //         .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
    //         .load::<BudgetShareEvent>(&mut db_connection)
    //         .unwrap();

    //     assert_eq!(share_events.len(), 0);

    //     let share_events = budget_share_events
    //         .filter(budget_share_event_fields::budget_id.eq(created_user2_budget.id))
    //         .load::<BudgetShareEvent>(&mut db_connection)
    //         .unwrap();

    //     assert_eq!(share_events.len(), 0);

    //     let budget_association = user_budgets
    //         .filter(user_budget_fields::user_id.eq(created_user1_id))
    //         .filter(user_budget_fields::budget_id.eq(created_user1_budget.id))
    //         .first::<UserBudget>(&mut db_connection);

    //     assert!(budget_association.is_err());

    //     let budget_association = user_budgets
    //         .filter(user_budget_fields::user_id.eq(created_user2_id))
    //         .filter(user_budget_fields::budget_id.eq(created_user1_budget.id))
    //         .first::<UserBudget>(&mut db_connection);

    //     assert!(budget_association.is_err());

    //     let budget = budgets
    //         .find(created_user1_budget.id)
    //         .get_result::<Budget>(&mut db_connection);

    //     assert!(budget.is_err());

    //     let req = test::TestRequest::get()
    //         .uri(&format!(
    //             "/api/budget/get?budget_id={}",
    //             budget_id.budget_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

    //     let req = test::TestRequest::get()
    //         .uri(&format!(
    //             "/api/budget/get?budget_id={}",
    //             budget_id.budget_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user2_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

    //     let budget_user2_id = InputBudgetId {
    //         budget_id: created_user2_budget.id,
    //     };

    //     let req = test::TestRequest::delete()
    //         .uri(&format!(
    //             "/api/budget/remove_budget?budget_id={}",
    //             budget_user2_id.budget_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user2_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let budget_association = user_budgets
    //         .filter(user_budget_fields::user_id.eq(created_user2_id))
    //         .filter(user_budget_fields::budget_id.eq(created_user2_budget.id))
    //         .first::<UserBudget>(&mut db_connection);

    //     assert!(budget_association.is_err());

    //     let budget = budgets
    //         .find(created_user2_budget.id)
    //         .get_result::<Budget>(&mut db_connection);

    //     assert!(budget.is_err());

    //     let req = test::TestRequest::get()
    //         .uri(&format!(
    //             "/api/budget/get?budget_id={}",
    //             budget_user2_id.budget_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user2_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    // }

    // #[actix_rt::test]
    // async fn test_cannot_delete_budget_for_another_user() {
    //     let db_thread_pool = &*env::testing::DB_THREAD_POOL;
    //     let mut db_connection = db_thread_pool.get().unwrap();

    //     let app = test::init_service(
    //         App::new()
    //             .app_data(Data::new(db_thread_pool.clone()))
    //             .configure(services::api::configure),
    //     )
    //     .await;

    //     let created_user1_and_budget =
    //         create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
    //     let created_user1_budget = created_user1_and_budget.budget;

    //     let created_user2_and_budget =
    //         create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
    //     let created_user2_id = created_user2_and_budget.user_id;

    //     let created_user3_and_budget =
    //         create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
    //     let created_user3_budget = created_user3_and_budget.budget;

    //     let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
    //     let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();
    //     let user3_access_token = created_user3_and_budget.token_pair.access_token.clone();

    //     let invitation_info_budget = UserInvitationToBudget {
    //         invitee_user_id: created_user2_id,
    //         budget_id: created_user1_budget.id,
    //     };

    //     let req = test::TestRequest::post()
    //         .uri("/api/budget/invite")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .set_json(&invitation_info_budget)
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let share_events = budget_share_events
    //         .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
    //         .load::<BudgetShareEvent>(&mut db_connection)
    //         .unwrap();

    //     assert_eq!(share_events.len(), 1);

    //     let invite_id = InputShareEventId {
    //         share_event_id: share_events[0].id,
    //     };

    //     let req = test::TestRequest::put()
    //         .uri(&format!(
    //             "/api/budget/accept_invitation?share_event_id={}",
    //             invite_id.share_event_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user2_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let budget_id = InputBudgetId {
    //         budget_id: created_user1_budget.id,
    //     };

    //     let req = test::TestRequest::post()
    //         .uri(&format!(
    //             "/api/budget/remove_budget?budget_id={}",
    //             budget_id.budget_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user3_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

    //     let budget = budgets
    //         .find(created_user1_budget.id)
    //         .load::<Budget>(&mut db_connection);

    //     assert!(budget.is_ok());

    //     let req = test::TestRequest::get()
    //         .uri(&format!(
    //             "/api/budget/get?budget_id={}",
    //             budget_id.budget_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let req = test::TestRequest::get()
    //         .uri(&format!(
    //             "/api/budget/get?budget_id={}",
    //             budget_id.budget_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user2_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let user3_budget_id = InputBudgetId {
    //         budget_id: created_user3_budget.id,
    //     };

    //     let req = test::TestRequest::post()
    //         .uri(&format!(
    //             "/api/budget/remove_budget?budget_id={}",
    //             user3_budget_id.budget_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user1_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

    //     let budget = budgets
    //         .find(created_user3_budget.id)
    //         .load::<Budget>(&mut db_connection);

    //     assert!(budget.is_ok());

    //     let req = test::TestRequest::get()
    //         .uri(&format!(
    //             "/api/budget/get?budget_id={}",
    //             user3_budget_id.budget_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {user3_access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);
    // }

    // #[actix_rt::test]
    // async fn test_get_budget() {
    //     let db_thread_pool = &*env::testing::DB_THREAD_POOL;

    //     let app = test::init_service(
    //         App::new()
    //             .app_data(Data::new(db_thread_pool.clone()))
    //             .configure(services::api::configure),
    //     )
    //     .await;

    //     let created_user_and_budget =
    //         create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
    //     let created_budget = created_user_and_budget.budget.clone();
    //     let access_token = created_user_and_budget.token_pair.access_token.clone();
    //     let budget_categories = created_budget.categories.clone();

    //     let entry0 = InputEntry {
    //         budget_id: created_budget.id,
    //         amount_cents: rand::thread_rng().gen_range(90..=120000),
    //         date: NaiveDate::from_ymd(
    //             2022,
    //             rand::thread_rng().gen_range(1..=6),
    //             rand::thread_rng().gen_range(1..=28),
    //         ),
    //         name: Some(format!("Test Entry 0 for user")),
    //         category: Some(0),
    //         note: Some(String::from("This is a little note")),
    //     };

    //     let entry1 = InputEntry {
    //         budget_id: created_budget.id,
    //         amount_cents: rand::thread_rng().gen_range(90..=120000),
    //         date: NaiveDate::from_ymd(
    //             2022,
    //             rand::thread_rng().gen_range(7..=12),
    //             rand::thread_rng().gen_range(1..=28),
    //         ),
    //         name: None,
    //         category: None,
    //         note: None,
    //     };

    //     let created_entries = vec![entry0.clone(), entry1.clone()];

    //     let entry0_req = test::TestRequest::post()
    //         .uri("/api/budget/add_entry")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {access_token}")))
    //         .set_json(&created_entries[0])
    //         .to_request();

    //     test::call_service(&app, entry0_req).await;

    //     let entry1_req = test::TestRequest::post()
    //         .uri("/api/budget/add_entry")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {access_token}")))
    //         .set_json(&created_entries[1])
    //         .to_request();

    //     test::call_service(&app, entry1_req).await;

    //     let input_budget_id = InputBudgetId {
    //         budget_id: created_budget.id,
    //     };

    //     let req = test::TestRequest::get()
    //         .uri(&format!(
    //             "/api/budget/get?budget_id={}",
    //             input_budget_id.budget_id
    //         ))
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {access_token}")))
    //         .to_request();

    //     let res = test::call_service(&app, req).await;
    //     assert_eq!(res.status(), http::StatusCode::OK);

    //     let res_body = String::from_utf8(actix_web::test::read_body(res).await.to_vec()).unwrap();
    //     let budget = serde_json::from_str::<OutputBudget>(res_body.as_str()).unwrap();

    //     assert_eq!(budget.id, created_budget.id);
    //     assert_eq!(budget.is_shared, created_budget.is_shared);
    //     assert_eq!(budget.is_private, created_budget.is_private);
    //     assert_eq!(budget.is_deleted, created_budget.is_deleted);
    //     assert_eq!(budget.name, created_budget.name);
    //     assert_eq!(budget.description, created_budget.description);
    //     assert_eq!(budget.start_date, created_budget.start_date);
    //     assert_eq!(budget.end_date, created_budget.end_date);

    //     assert!(budget.latest_entry_time > created_budget.latest_entry_time);

    //     assert_eq!(budget.modified_timestamp, created_budget.modified_timestamp);
    //     assert_eq!(budget.created_timestamp, created_budget.created_timestamp);

    //     assert!(!budget.categories.is_empty());
    //     assert_eq!(budget.categories.len(), created_budget.categories.len());

    //     for i in 0..budget_categories.len() {
    //         let fetched_cat = &budget.categories[i];
    //         let created_cat = &created_budget.categories[i];

    //         assert_eq!(fetched_cat.pk, created_cat.pk);
    //         assert_eq!(fetched_cat.budget_id, created_cat.budget_id);
    //         assert_eq!(fetched_cat.id, created_cat.id);
    //         assert_eq!(fetched_cat.name, created_cat.name);
    //         assert_eq!(fetched_cat.limit_cents, created_cat.limit_cents);
    //         assert_eq!(fetched_cat.color, created_cat.color);
    //     }

    //     for i in 0..created_entries.len() {
    //         assert_eq!(
    //             budget.entries[i].amount_cents,
    //             created_entries[i].amount_cents
    //         );
    //         assert_eq!(budget.entries[i].date, created_entries[i].date);
    //         assert_eq!(budget.entries[i].name, created_entries[i].name);
    //         assert_eq!(budget.entries[i].category, created_entries[i].category);
    //         assert_eq!(budget.entries[i].note, created_entries[i].note);
    //     }
    // }

    // #[actix_rt::test]
    // async fn test_get_all_budgets_for_user() {
    //     let db_thread_pool = &*env::testing::DB_THREAD_POOL;

    //     let app = test::init_service(
    //         App::new()
    //             .app_data(Data::new(db_thread_pool.clone()))
    //             .configure(services::api::configure),
    //     )
    //     .await;

    //     let created_user_and_budget =
    //         create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
    //     let created_budget0 = created_user_and_budget.budget.clone();
    //     let access_token = created_user_and_budget.token_pair.access_token.clone();

    //     let mut budget_categories = Vec::new();
    //     budget_categories.push(InputCategory {
    //         id: created_budget0.categories[0].id,
    //         name: created_budget0.categories[0].name.clone(),
    //         limit_cents: created_budget0.categories[0].limit_cents,
    //         color: created_budget0.categories[0].color.clone(),
    //     });

    //     budget_categories.push(InputCategory {
    //         id: created_budget0.categories[1].id,
    //         name: created_budget0.categories[1].name.clone(),
    //         limit_cents: created_budget0.categories[1].limit_cents,
    //         color: created_budget0.categories[1].color.clone(),
    //     });

    //     let new_budget1 = InputBudget {
    //         name: format!("Test Budget user"),
    //         description: Some(format!("This is a description of Test Budget user.",)),
    //         categories: budget_categories.clone(),
    //         start_date: NaiveDate::from_ymd(
    //             2022,
    //             rand::thread_rng().gen_range(1..=12),
    //             rand::thread_rng().gen_range(1..=28),
    //         ),
    //         end_date: NaiveDate::from_ymd(
    //             2023,
    //             rand::thread_rng().gen_range(1..=12),
    //             rand::thread_rng().gen_range(1..=28),
    //         ),
    //     };

    //     let create_budget1_req = test::TestRequest::post()
    //         .uri("/api/budget/create")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {access_token}")))
    //         .set_json(&new_budget1)
    //         .to_request();

    //     let create_budget1_resp = test::call_service(&app, create_budget1_req).await;
    //     let create_budget1_res_body = String::from_utf8(
    //         actix_web::test::read_body(create_budget1_resp)
    //             .await
    //             .to_vec(),
    //     )
    //     .unwrap();

    //     let created_budget1 =
    //         serde_json::from_str::<OutputBudget>(create_budget1_res_body.as_str()).unwrap();

    //     let created_budgets = vec![created_budget0.clone(), created_budget1.clone()];

    //     let entry0 = InputEntry {
    //         budget_id: created_budget0.id,
    //         amount_cents: rand::thread_rng().gen_range(90..=120000),
    //         date: NaiveDate::from_ymd(
    //             2022,
    //             rand::thread_rng().gen_range(1..=6),
    //             rand::thread_rng().gen_range(1..=28),
    //         ),
    //         name: Some(format!("Test Entry 0 for user")),
    //         category: Some(0),
    //         note: Some(String::from("This is a little note")),
    //     };

    //     let entry1 = InputEntry {
    //         budget_id: created_budget0.id,
    //         amount_cents: rand::thread_rng().gen_range(90..=120000),
    //         date: NaiveDate::from_ymd(
    //             2022,
    //             rand::thread_rng().gen_range(7..=12),
    //             rand::thread_rng().gen_range(1..=28),
    //         ),
    //         name: None,
    //         category: None,
    //         note: None,
    //     };

    //     let entry2 = InputEntry {
    //         budget_id: created_budget1.id,
    //         amount_cents: rand::thread_rng().gen_range(90..=120000),
    //         date: NaiveDate::from_ymd(
    //             2022,
    //             rand::thread_rng().gen_range(1..=6),
    //             rand::thread_rng().gen_range(1..=28),
    //         ),
    //         name: Some(format!("Test Entry 2 for user")),
    //         category: Some(0),
    //         note: Some(String::from("This is a little note")),
    //     };

    //     let entry3 = InputEntry {
    //         budget_id: created_budget1.id,
    //         amount_cents: rand::thread_rng().gen_range(90..=120000),
    //         date: NaiveDate::from_ymd(
    //             2022,
    //             rand::thread_rng().gen_range(7..=12),
    //             rand::thread_rng().gen_range(1..=28),
    //         ),
    //         name: None,
    //         category: None,
    //         note: None,
    //     };

    //     let created_entries = vec![
    //         vec![entry0.clone(), entry1.clone()],
    //         vec![entry2.clone(), entry3.clone()],
    //     ];

    //     let entry0_req = test::TestRequest::post()
    //         .uri("/api/budget/add_entry")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {access_token}")))
    //         .set_json(&entry0)
    //         .to_request();

    //     test::call_service(&app, entry0_req).await;

    //     let entry1_req = test::TestRequest::post()
    //         .uri("/api/budget/add_entry")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {access_token}")))
    //         .set_json(&entry1)
    //         .to_request();

    //     test::call_service(&app, entry1_req).await;

    //     let entry2_req = test::TestRequest::post()
    //         .uri("/api/budget/add_entry")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {access_token}")))
    //         .set_json(&entry2)
    //         .to_request();

    //     test::call_service(&app, entry2_req).await;

    //     let entry3_req = test::TestRequest::post()
    //         .uri("/api/budget/add_entry")
    //         .insert_header(("content-type", "application/json"))
    //         .insert_header(("authorization", format!("bearer {access_token}")))
    //         .set_json(&entry3)
    //         .to_request();

    //     test::call_service(&app, entry3_req).await;

    //     let req = test::TestRequest::get()
    //         .uri("/api/budget/get_all")
    //         .insert_header(("authorization", format!("bearer {access_token}")))
    //         .to_request();

    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);

    //     let res_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
    //     let output_budgets = serde_json::from_str::<Vec<OutputBudget>>(res_body.as_str()).unwrap();
    //     assert_eq!(output_budgets.len(), 2);

    //     for i in 0..output_budgets.len() {
    //         let budget = &output_budgets[i];
    //         let created_budget = &created_budgets[i];

    //         assert_eq!(budget.id, created_budget.id);
    //         assert_eq!(budget.is_shared, created_budget.is_shared);
    //         assert_eq!(budget.is_private, created_budget.is_private);
    //         assert_eq!(budget.is_deleted, created_budget.is_deleted);
    //         assert_eq!(budget.name, created_budget.name);
    //         assert_eq!(budget.description, created_budget.description);
    //         assert_eq!(budget.start_date, created_budget.start_date);
    //         assert_eq!(budget.end_date, created_budget.end_date);

    //         assert!(budget.latest_entry_time > created_budget.latest_entry_time);

    //         assert_eq!(budget.modified_timestamp, created_budget.modified_timestamp);
    //         assert_eq!(budget.created_timestamp, created_budget.created_timestamp);

    //         assert!(!budget.categories.is_empty());
    //         assert_eq!(budget.categories.len(), created_budget.categories.len());

    //         for j in 0..budget_categories.len() {
    //             let fetched_cat = &budget.categories[j];
    //             let created_cat = &created_budget.categories[j];

    //             assert_eq!(fetched_cat.pk, created_cat.pk);
    //             assert_eq!(fetched_cat.budget_id, created_cat.budget_id);
    //             assert_eq!(fetched_cat.id, created_cat.id);
    //             assert_eq!(fetched_cat.name, created_cat.name);
    //             assert_eq!(fetched_cat.limit_cents, created_cat.limit_cents);
    //             assert_eq!(fetched_cat.color, created_cat.color);
    //         }

    //         for j in 0..created_entries[i].len() {
    //             assert_eq!(
    //                 budget.entries[j].amount_cents,
    //                 created_entries[i][j].amount_cents
    //             );
    //             assert_eq!(budget.entries[j].date, created_entries[i][j].date);
    //             assert_eq!(budget.entries[j].name, created_entries[i][j].name);
    //             assert_eq!(budget.entries[j].category, created_entries[i][j].category);
    //             assert_eq!(budget.entries[j].note, created_entries[i][j].note);
    //         }
    //     }
    // }
}
