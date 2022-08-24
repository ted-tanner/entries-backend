use actix_web::{web, HttpResponse};
use log::error;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::definitions::DbThreadPool;
use crate::env;
use crate::handlers::error::ServerError;
use crate::handlers::request_io::{
    CurrentAndNewPasswordPair, InputBuddyRequestId, InputEditUser, InputUser, InputUserId,
    OutputUserPrivate, SigninToken,
};
use crate::middleware;
use crate::utils::db;
use crate::utils::{auth_token, otp, password_hasher, validators};

// TODO: Get another user by ID when an optional query param is passed
pub async fn get(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let user = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        db::user::get_user_by_id(&db_connection, auth_user_claims.0.uid)
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
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to get user data",
                )));
            }
        },
    };

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
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::create_user(&db_connection, &user_data)
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
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::edit_user(&db_connection, auth_user_claims.0.uid, &user_data)
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
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::get_user_by_id(&db_connection, auth_user_claims.0.uid)
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
        let db_connection = db_thread_pool_pointer_copy
            .get()
            .expect("Failed to access database thread pool");

        db::user::change_password(
            &db_connection,
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
    match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::send_buddy_request(
            &db_connection,
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
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::delete_buddy_request(
            &db_connection,
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
        let db_connection = db_thread_pool_ref
            .get()
            .expect("Failed to access database thread pool");

        db::user::mark_buddy_request_accepted(&db_connection, request_id, auth_user_claims.0.uid)
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
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::create_buddy_relationship(
            &db_connection,
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
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::mark_buddy_request_declined(
            &db_connection,
            request_id.buddy_request_id,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(count) => {
            if count == 0 {
                return Err(ServerError::UserUnauthorized(Some(
                    "User not authorized to decline buddy request",
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
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::get_all_pending_buddy_requests_for_user(&db_connection, auth_user_claims.0.uid)
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
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::get_all_pending_buddy_requests_made_by_user(
            &db_connection,
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
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::get_buddy_request(
            &db_connection,
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
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::delete_buddy_relationship(
            &db_connection,
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
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::user::get_buddies(&db_connection, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to find buddies for user",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().json(buddies))
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::web::Data;
    use actix_web::{http, test, App};
    use chrono::NaiveDate;
    use diesel::prelude::*;
    use rand::prelude::*;

    use crate::env;
    use crate::handlers::request_io::{SigninTokenOtpPair, TokenPair};
    use crate::models::user::User;
    use crate::schema::users as user_fields;
    use crate::schema::users::dsl::users;
    use crate::services;
    use crate::utils::auth_token::TokenClaims;

    #[actix_rt::test]
    async fn test_create() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);

        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        let req = test::TestRequest::post()
            .uri("/api/user/create")
            .insert_header(("content-type", "application/json"))
            .set_json(&new_user)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::CREATED);

        let db_connection = db_thread_pool.get().unwrap();

        let created_user = users
            .filter(user_fields::email.eq(&new_user.email.to_lowercase()))
            .first::<User>(&db_connection)
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

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("1dIbCx^n@VF9f&0*c*39"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
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
            date_of_birth: new_user.date_of_birth.clone(),
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

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);

        let new_user = InputUser {
            email: format!("test_user{}test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
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

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);

        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("Password1234"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
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
    async fn test_get() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("1dIbCx^n@VF9f&0*c*39"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
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
    async fn test_change_password() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("tNmUV%9$khHK2TqOLw*%W"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
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

        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        let db_password_hash = db::user::get_user_by_id(&db_connection, user_id)
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

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("tNmUV%9$khHK2TqOLw*%W"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
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

        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        let db_password_hash = db::user::get_user_by_id(&db_connection, user_id)
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

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("tNmUV%9$khHK2TqOLw*%W"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
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

        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        let db_password_hash = db::user::get_user_by_id(&db_connection, user_id)
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
}
