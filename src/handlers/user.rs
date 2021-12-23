use actix_web::{web, HttpResponse};
use log::error;

use crate::db_utils;
use crate::definitions::ThreadPool;
use crate::handlers::request_io::InputUser;
use crate::handlers::request_io::OutputUserPrivate;
use crate::middleware;
use crate::utils::jwt;

pub async fn get(
    thread_pool: web::Data<ThreadPool>,
    auth_user: middleware::auth::AuthorizedUserId,
) -> Result<HttpResponse, actix_web::Error> {
    let db_connection = thread_pool.get().expect("Failed to access thread pool");

    Ok(
        web::block(move || db_utils::user::get_user_by_id(&db_connection, &auth_user.0))
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

                HttpResponse::Ok().json(output_user)
            })
            .map_err(|ref e| match e {
                actix_web::error::BlockingError::Error(err) => match err {
                    diesel::result::Error::InvalidCString(_)
                    | diesel::result::Error::DeserializationError(_) => {
                        HttpResponse::BadRequest().body("Invalid format")
                    }
                    diesel::result::Error::NotFound => {
                        HttpResponse::Forbidden().body("No user with ID")
                    }
                    _ => {
                        error!("{}", e);
                        HttpResponse::InternalServerError().body("Failed to get user data")
                    }
                },
                actix_web::error::BlockingError::Canceled => {
                    error!("{}", e);
                    HttpResponse::InternalServerError().body("Database transaction canceled")
                }
            })?,
    )
}

pub async fn create(
    thread_pool: web::Data<ThreadPool>,
    user_data: web::Json<InputUser>,
) -> Result<HttpResponse, actix_web::Error> {
    if !user_data.validate_email_address() {
        return Ok(HttpResponse::BadRequest().body("Invalid email address"));
    }

    match user_data.validate_strong_password() {
        db_utils::PasswordValidity::VALID => {}
        db_utils::PasswordValidity::INVALID(msg) => return Ok(HttpResponse::BadRequest().body(msg)),
    }

    let db_connection = thread_pool.get().expect("Failed to access thread pool");

    Ok(
        web::block(move || db_utils::user::create_user(&db_connection, &user_data))
            .await
            .map(|user| {
                let token_pair = jwt::generate_token_pair(user.id);

                let token_pair = match token_pair {
                    Ok(token_pair) => token_pair,
                    Err(e) => {
                        error!("{}", e);
                        return HttpResponse::InternalServerError()
                            .body("Failed to generate tokens for new user. User has been created");
                    }
                };

                HttpResponse::Created().json(token_pair)
            })
            .map_err(|ref e| match e {
                actix_web::error::BlockingError::Error(err) => match err {
                    diesel::result::Error::InvalidCString(_)
                    | diesel::result::Error::DeserializationError(_) => {
                        HttpResponse::BadRequest().body("Invalid format")
                    }
                    diesel::result::Error::NotFound => {
                        HttpResponse::Forbidden().body("No user with ID")
                    }
                    diesel::result::Error::DatabaseError(error_kind, _) => match error_kind {
                        diesel::result::DatabaseErrorKind::UniqueViolation => {
                            HttpResponse::BadRequest()
                                .body("A user with the given email already exists")
                        }
                        _ => {
                            error!("{}", e);
                            HttpResponse::InternalServerError().body("Failed to create user")
                        }
                    },
                    _ => {
                        error!("{}", e);
                        HttpResponse::InternalServerError().body("Failed to create user")
                    }
                },
                actix_web::error::BlockingError::Canceled => {
                    error!("{}", e);
                    HttpResponse::InternalServerError().body("Database transaction canceled")
                }
            })?,
    )
}

#[cfg(test)]
mod test {
    use super::*;

    use actix_web::{http, test, App};
    use chrono::NaiveDate;
    use diesel::prelude::*;
    use diesel::r2d2::{self, ConnectionManager};
    use rand::prelude::*;

    use crate::db_utils;
    use crate::env;
    use crate::handlers::request_io::InputUser;
    use crate::handlers::request_io::OutputUserPrivate;
    use crate::models::user::User;
    use crate::schema::users as user_fields;
    use crate::schema::users::dsl::users;
    use crate::utils::jwt;

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

    // TODO: Create user with create user endpoint for this integration test
    #[actix_rt::test]
    async fn test_get() {
        let manager = ConnectionManager::<PgConnection>::new(env::db::DATABASE_URL.as_str());
        let thread_pool = r2d2::Pool::builder().build(manager).unwrap();

        let mut app = test::init_service(
            App::new()
                .data(thread_pool.clone())
                .route("/api/user/get", web::get().to(get)),
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

        let new_user_json = web::Json(new_user.clone());

        let db_connection = thread_pool.get().unwrap();
        let user_id = db_utils::user::create_user(&db_connection, &new_user_json)
            .unwrap()
            .id;

        let user_token = jwt::generate_access_token(user_id)
            .unwrap()
            .to_string();

        let req = test::TestRequest::get()
            .uri("/api/user/get")
            .header("content-type", "application/json")
            .header("authorization", format!("bearer {}", &user_token).as_str())
            .to_request();

        let res = test::call_service(&mut app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(res).await.to_vec()).unwrap();
        let user_from_res: OutputUserPrivate = serde_json::from_str(res_body.as_str()).unwrap();

        assert_eq!(&new_user.email, &user_from_res.email);
        assert_eq!(&new_user.first_name, &user_from_res.first_name);
        assert_eq!(&new_user.last_name, &user_from_res.last_name);
        assert_eq!(&new_user.date_of_birth, &user_from_res.date_of_birth);
        assert_eq!(&new_user.currency, &user_from_res.currency);
    }
}
