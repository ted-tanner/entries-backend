use actix_web::{web, HttpResponse};
use log::error;

use crate::db_utils;
use crate::definitions::ThreadPool;
use crate::handlers::error::ServerError;
pub(crate) use crate::handlers::request_io::{
    CurrentAndNewPasswordPair, InputUser, OutputUserPrivate,
};
use crate::middleware;
pub(crate) use crate::utils::{jwt, password_hasher, validators};

pub async fn get(
    thread_pool: web::Data<ThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    web::block(move || {
        let db_connection = thread_pool.get().expect("Failed to access thread pool");
        db_utils::user::get_user_by_id(&db_connection, &auth_user_claims.0.uid)
    })
    .await
    .map(|user| {
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
    })
    .map_err(|ref e| match e {
        actix_web::error::BlockingError::Error(err) => match err {
            diesel::result::Error::InvalidCString(_)
            | diesel::result::Error::DeserializationError(_) => {
                Err(ServerError::InvalidFormat(None))
            }
            diesel::result::Error::NotFound => {
                Err(ServerError::AccessForbidden(Some("No user with ID")))
            }
            _ => {
                error!("{}", e);

                Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to get user data",
                )))
            }
        },
        actix_web::error::BlockingError::Canceled => {
            error!("{}", e);

            Err(ServerError::DatabaseTransactionError(Some(
                "Database transaction canceled",
            )))
        }
    })?
}

pub async fn create(
    thread_pool: web::Data<ThreadPool>,
    user_data: web::Json<InputUser>,
) -> Result<HttpResponse, ServerError> {
    if !&user_data.0.validate_email_address().is_valid() {
        return Err(ServerError::InvalidFormat(Some("Invalid email address")));
    }

    if let validators::Validity::INVALID(msg) = user_data.0.validate_strong_password() {
        return Err(ServerError::InputRejected(Some(msg)));
    }

    web::block(move || {
        let db_connection = thread_pool.get().expect("Failed to access thread pool");
        db_utils::user::create_user(&db_connection, &user_data)
    })
    .await
    .map(|user| {
        let token_pair = jwt::generate_token_pair(&user.id);

        let token_pair = match token_pair {
            Ok(token_pair) => token_pair,
            Err(e) => {
                error!("{}", e);

                return Err(ServerError::InternalServerError(Some(
                    "User has been created, but token generation failed. Try signing in.",
                )));
            }
        };

        Ok(HttpResponse::Created().json(token_pair))
    })
    .map_err(|ref e| match e {
        actix_web::error::BlockingError::Error(err) => match err {
            diesel::result::Error::InvalidCString(_)
            | diesel::result::Error::DeserializationError(_) => {
                Err(ServerError::InvalidFormat(None))
            }
            diesel::result::Error::NotFound => {
                Err(ServerError::AccessForbidden(Some("No user with ID")))
            }
            diesel::result::Error::DatabaseError(error_kind, _) => match error_kind {
                diesel::result::DatabaseErrorKind::UniqueViolation => Err(
                    ServerError::AlreadyExists(Some("A user with the given email already exists")),
                ),
                _ => {
                    error!("{}", e);
                    Err(ServerError::InternalServerError(Some(
                        "Failed to create user",
                    )))
                }
            },
            _ => {
                error!("{}", e);
                Err(ServerError::InternalServerError(Some(
                    "Failed to create user",
                )))
            }
        },
        actix_web::error::BlockingError::Canceled => {
            error!("{}", e);
            Err(ServerError::InternalServerError(Some(
                "Database transaction canceled",
            )))
        }
    })?
}

/// ## Test cases:
///     * old_password wrong
///     * new_password invalid
///     * normal case
pub async fn change_password(
    thread_pool: web::Data<ThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    password_pair: web::Json<CurrentAndNewPasswordPair>,
) -> Result<HttpResponse, ServerError> {
    let db_connection = thread_pool.get().expect("Failed to access thread pool");

    let user =
        web::block(move || db_utils::user::get_user_by_id(&db_connection, &auth_user_claims.0.uid))
            .await
            .map_err(|_| ServerError::InputRejected(Some("User not found")))?;

    let current_password = password_pair.current_password.clone();

    let does_password_match_hash = web::block(move || {
        Ok(password_hasher::verify_hash(
            &current_password,
            &user.password_hash,
        ))
        .map_err(|_: ServerError| ServerError::InternalServerError(None))
    })
    .await
    .expect("Failed to block on password verification");

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

    if let validators::Validity::INVALID(msg) = new_password_validity {
        return Err(ServerError::InputRejected(Some(msg)));
    };

    let db_connection = thread_pool.get().expect("Failed to access thread pool");

    web::block(move || {
        db_utils::user::change_password(
            &db_connection,
            &auth_user_claims.0.uid,
            &password_pair.new_password,
        )
    })
    .await
    .map(|_| HttpResponse::Ok().finish())
    .map_err(|_| ServerError::DatabaseTransactionError(Some("Failed to update password")))
}

#[cfg(test)]
mod test {
    use super::*;

    use actix_web::{http, test, App};
    use chrono::NaiveDate;
    use diesel::prelude::*;
    use diesel::r2d2::{self, ConnectionManager};
    use rand::prelude::*;

    use crate::env;
    use crate::models::user::User;
    use crate::schema::users as user_fields;
    use crate::schema::users::dsl::users;

    #[actix_rt::test]
    async fn test_create() {
        let manager = ConnectionManager::<PgConnection>::new(env::db::DATABASE_URL.as_str());
        let thread_pool = r2d2::Pool::builder().build(manager).unwrap();

        let mut app = test::init_service(
            App::new()
                .data(thread_pool.clone())
                .route("/api/user/create", web::post().to(create)),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);

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
            .header("content-type", "application/json")
            .set_json(&new_user)
            .to_request();

        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), http::StatusCode::CREATED);

        let db_connection = thread_pool.get().unwrap();

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
    async fn test_create_fails_with_invalid_email() {
        let manager = ConnectionManager::<PgConnection>::new(env::db::DATABASE_URL.as_str());
        let thread_pool = r2d2::Pool::builder().build(manager).unwrap();

        let mut app = test::init_service(
            App::new()
                .data(thread_pool.clone())
                .route("/api/user/create", web::post().to(create)),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);

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
            .header("content-type", "application/json")
            .set_json(&new_user)
            .to_request();

        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn test_create_fails_with_invalid_password() {
        let manager = ConnectionManager::<PgConnection>::new(env::db::DATABASE_URL.as_str());
        let thread_pool = r2d2::Pool::builder().build(manager).unwrap();

        let mut app = test::init_service(
            App::new()
                .data(thread_pool.clone())
                .route("/api/user/create", web::post().to(create)),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);

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
            .header("content-type", "application/json")
            .set_json(&new_user)
            .to_request();

        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn test_get() {
        let manager = ConnectionManager::<PgConnection>::new(env::db::DATABASE_URL.as_str());
        let thread_pool = r2d2::Pool::builder().build(manager).unwrap();

        let mut app = test::init_service(
            App::new()
                .data(thread_pool.clone())
                .route("/api/user/get", web::get().to(get))
                .route("/api/user/create", web::post().to(create)),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
        .await;

        let user_tokens =
            actix_web::test::read_body_json::<jwt::TokenPair, _>(create_user_res).await;
        let access_token = user_tokens.access_token.to_string();

        let req = test::TestRequest::get()
            .uri("/api/user/get")
            .header(
                "authorization",
                format!("bearer {}", &access_token).as_str(),
            )
            .to_request();

        let res = test::call_service(&mut app, req).await;
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
        let manager = ConnectionManager::<PgConnection>::new(env::db::DATABASE_URL.as_str());
        let thread_pool = r2d2::Pool::builder().build(manager).unwrap();

        let mut app = test::init_service(
            App::new()
                .data(thread_pool.clone())
                .route("/api/user/change_password", web::post().to(change_password))
                .route("/api/user/create", web::post().to(create)),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
        .await;

        let user_tokens =
            actix_web::test::read_body_json::<jwt::TokenPair, _>(create_user_res).await;
        let access_token = user_tokens.access_token.to_string();
        let user_id = jwt::read_claims(&access_token).unwrap().uid;

        let password_pair = CurrentAndNewPasswordPair {
            current_password: new_user.password.clone(),
            new_password: String::from("s$B5Pl@KC7t92&a!jZ3Gx"),
        };

        let req = test::TestRequest::post()
            .uri("/api/user/change_password")
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!("bearer {}", &access_token).as_str(),
            )
            .set_payload(serde_json::ser::to_vec(&password_pair).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;

        assert_eq!(res.status(), http::StatusCode::OK);

        let db_connection = thread_pool.get().expect("Failed to access thread pool");
        let db_password_hash = db_utils::user::get_user_by_id(&db_connection, &user_id)
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
        let manager = ConnectionManager::<PgConnection>::new(env::db::DATABASE_URL.as_str());
        let thread_pool = r2d2::Pool::builder().build(manager).unwrap();

        let mut app = test::init_service(
            App::new()
                .data(thread_pool.clone())
                .route("/api/user/change_password", web::post().to(change_password))
                .route("/api/user/create", web::post().to(create)),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
        .await;

        let user_tokens =
            actix_web::test::read_body_json::<jwt::TokenPair, _>(create_user_res).await;
        let access_token = user_tokens.access_token.to_string();
        let user_id = jwt::read_claims(&access_token).unwrap().uid;

        let password_pair = CurrentAndNewPasswordPair {
            current_password: new_user.password.clone() + " ",
            new_password: String::from("s$B5Pl@KC7t92&a!jZ3Gx"),
        };

        let req = test::TestRequest::post()
            .uri("/api/user/change_password")
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!("bearer {}", &access_token).as_str(),
            )
            .set_payload(serde_json::ser::to_vec(&password_pair).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;

        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);

        let db_connection = thread_pool.get().expect("Failed to access thread pool");
        let db_password_hash = db_utils::user::get_user_by_id(&db_connection, &user_id)
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
        let manager = ConnectionManager::<PgConnection>::new(env::db::DATABASE_URL.as_str());
        let thread_pool = r2d2::Pool::builder().build(manager).unwrap();

        let mut app = test::init_service(
            App::new()
                .data(thread_pool.clone())
                .route("/api/user/change_password", web::post().to(change_password))
                .route("/api/user/create", web::post().to(create)),
        )
        .await;

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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
            &mut app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .header("content-type", "application/json")
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
        .await;

        let user_tokens =
            actix_web::test::read_body_json::<jwt::TokenPair, _>(create_user_res).await;
        let access_token = user_tokens.access_token.to_string();
        let user_id = jwt::read_claims(&access_token).unwrap().uid;

        let password_pair = CurrentAndNewPasswordPair {
            current_password: new_user.password.clone(),
            new_password: String::from("Password1234"),
        };

        let req = test::TestRequest::post()
            .uri("/api/user/change_password")
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!("bearer {}", &access_token).as_str(),
            )
            .set_payload(serde_json::ser::to_vec(&password_pair).unwrap())
            .to_request();

        let res = test::call_service(&mut app, req).await;

        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);

        let db_connection = thread_pool.get().expect("Failed to access thread pool");
        let db_password_hash = db_utils::user::get_user_by_id(&db_connection, &user_id)
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
