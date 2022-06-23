use actix_web::{web, HttpResponse};
use log::error;
use uuid::Uuid;

use crate::definitions::DbThreadPool;
use crate::handlers::error::ServerError;
use crate::handlers::request_io::{
    InputBudget, InputBudgetId, InputDateRange, InputEditBudget, InputEntry, OutputBudget,
};
use crate::middleware;
use crate::utils::db;

pub async fn get(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    budget_id: web::Json<InputBudgetId>,
) -> Result<HttpResponse, ServerError> {
    let budget_id_clone = budget_id.budget_id;

    ensure_user_in_budget(
        db_thread_pool.clone(),
        auth_user_claims.0.uid,
        budget_id_clone,
    )
    .await?;

    let budget = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        db::budget::get_budget_by_id(&db_connection, budget_id.budget_id)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            diesel::result::Error::InvalidCString(_)
            | diesel::result::Error::DeserializationError(_) => {
                return Err(ServerError::InvalidFormat(None));
            }
            diesel::result::Error::NotFound => {
                return Err(ServerError::AccessForbidden(Some("No budget with ID")));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to get budget data",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().json(budget))
}

pub async fn get_all(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let budgets = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        db::budget::get_all_budgets_for_user(&db_connection, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            diesel::result::Error::InvalidCString(_)
            | diesel::result::Error::DeserializationError(_) => {
                return Err(ServerError::InvalidFormat(None));
            }
            diesel::result::Error::NotFound => {
                return Ok(HttpResponse::Ok().json(Vec::<OutputBudget>::new()));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to get budget data",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().json(budgets))
}

pub async fn get_all_between_dates(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    date_range: web::Json<InputDateRange>,
) -> Result<HttpResponse, ServerError> {
    let budgets = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        db::budget::get_all_budgets_for_user_between_dates(
            &db_connection,
            auth_user_claims.0.uid,
            date_range.start_date,
            date_range.end_date,
        )
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            diesel::result::Error::InvalidCString(_)
            | diesel::result::Error::DeserializationError(_) => {
                return Err(ServerError::InvalidFormat(None))
            }
            diesel::result::Error::NotFound => {
                return Ok(HttpResponse::Ok().json(Vec::<OutputBudget>::new()));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to get budget data",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().json(budgets))
}

pub async fn create(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    budget_data: web::Json<InputBudget>,
) -> Result<HttpResponse, ServerError> {
    let new_budget = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        db::budget::create_budget(&db_connection, &budget_data, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            diesel::result::Error::InvalidCString(_)
            | diesel::result::Error::DeserializationError(_) => {
                return Err(ServerError::InvalidFormat(None));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to create budget",
                )));
            }
        },
    };

    Ok(HttpResponse::Created().json(new_budget))
}

pub async fn edit(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    budget_data: web::Json<InputEditBudget>,
) -> Result<HttpResponse, ServerError> {
    if budget_data.start_date > budget_data.end_date {
        return Err(ServerError::InputRejected(Some(
            "End date cannot come before start date",
        )));
    }

    let budget_id = budget_data.id.clone();
    ensure_user_in_budget(db_thread_pool.clone(), auth_user_claims.0.uid, budget_id).await?;

    web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::budget::edit_budget(&db_connection, &budget_data)
    })
    .await
    .map(|_| HttpResponse::Ok().finish())
    .map_err(|e| {
        error!("{}", e);
        ServerError::DatabaseTransactionError(Some("Failed to edit budget"))
    })
}

pub async fn add_entry(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    entry_data: web::Json<InputEntry>,
) -> Result<HttpResponse, ServerError> {
    let budget_id = entry_data.budget_id;
    ensure_user_in_budget(db_thread_pool.clone(), auth_user_claims.0.uid, budget_id).await?;

    let new_entry = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        db::budget::create_entry(&db_connection, &entry_data, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            diesel::result::Error::InvalidCString(_)
            | diesel::result::Error::DeserializationError(_) => {
                return Err(ServerError::InvalidFormat(None));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to create entry",
                )));
            }
        },
    };

    Ok(HttpResponse::Created().json(new_entry))
}

// // TODO: Test
// pub async fn invite_user(
//     db_thread_pool: web::Data<DbThreadPool>,
//     auth_user_claims: middleware::auth::AuthorizedUserClaims,
//     invitation_info: web::Json<UserInvitationToBudget>,
// ) -> Result<HttpResponse, ServerError> {
//     let inviting_user_id = auth_user_claims.0.uid.clone();
//     ensure_user_in_budget(db_thread_pool.clone(), inviting_user_id, invitation_info.budget_id.clone())
//         .await?;

//     // TODO
// }

// // TODO: Test
// pub async fn accept_invitation(
//     db_thread_pool: web::Data<DbThreadPool>,
//     auth_user_claims: middleware::auth::AuthorizedUserClaims,
//     invitation_info: web::Json<UserInvitationToBudget>,
// ) -> Result<HttpResponse, ServerError> {

// }

// // TODO: Test
// pub async fn remove_budget(
//     db_thread_pool: web::Data<DbThreadPool>,
//     auth_user_claims: middleware::auth::AuthorizedUserClaims,
//     budget_id: web::Json<Uuid>,
// ) -> Result<HttpResponse, ServerError> {
//     // TODO: Delete relationship if not last user in budget. Otherwise, delete budget
//     // entirely
// }

#[inline]
async fn ensure_user_in_budget(
    db_thread_pool: web::Data<DbThreadPool>,
    user_id: Uuid,
    budget_id: Uuid,
) -> Result<(), ServerError> {
    let is_user_in_budget = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::budget::check_user_in_budget(&db_connection, user_id, budget_id)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            diesel::result::Error::InvalidCString(_)
            | diesel::result::Error::DeserializationError(_) => {
                return Err(ServerError::InvalidFormat(None));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to get budget data",
                )));
            }
        },
    };

    if !is_user_in_budget {
        return Err(ServerError::NotFound(Some(
            "User has no budget with provided ID",
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use actix_web::web::Data;
    use actix_web::{http, test, App};
    use chrono::NaiveDate;
    use diesel::prelude::*;
    use rand::prelude::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::env;
    use crate::handlers::request_io::{
        InputBudget, InputBudgetId, InputCategory, InputDateRange, InputEditBudget, InputEntry,
        InputUser, OutputBudget, SigninToken, SigninTokenOtpPair, TokenPair,
    };
    use crate::models::budget::Budget;
    use crate::models::category::Category;
    use crate::models::entry::Entry;
    use crate::schema::budgets as budget_fields;
    use crate::schema::budgets::dsl::budgets;
    use crate::schema::entries as entry_fields;
    use crate::services;
    use crate::utils::{db, jwt, otp};

    #[actix_rt::test]
    async fn test_create_budget() {
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
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

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
        let access_token = token_pair.access_token.to_string();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let new_budget = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(
                2021,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            end_date: NaiveDate::from_ymd(
                2023,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&new_budget)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::CREATED);

        let db_connection = db_thread_pool.get().unwrap();

        let created_budget = budgets
            .filter(budget_fields::name.eq(&new_budget.name))
            .filter(budget_fields::start_date.eq(&new_budget.start_date))
            .first::<Budget>(&db_connection)
            .unwrap();

        let created_categories = Category::belonging_to(&created_budget)
            .load::<Category>(&db_connection)
            .unwrap();

        let created_entries = Entry::belonging_to(&created_budget)
            .load::<Entry>(&db_connection)
            .unwrap();

        assert_eq!(&new_budget.name, &created_budget.name);
        assert_eq!(&new_budget.description, &created_budget.description);
        assert_eq!(&new_budget.start_date, &created_budget.start_date);
        assert_eq!(&new_budget.end_date, &created_budget.end_date);

        assert!(created_entries.is_empty());

        for i in 0..created_categories.len() {
            let created_cat = &created_categories[i];
            let new_cat = &new_budget.categories[i];

            assert_eq!(created_cat.budget_id, created_budget.id);
            assert_eq!(created_cat.id, new_cat.id);
            assert_eq!(created_cat.name, new_cat.name);
            assert_eq!(created_cat.limit_cents, new_cat.limit_cents);
            assert_eq!(created_cat.color, new_cat.color);
        }
    }

    #[actix_rt::test]
    async fn test_edit_budget() {
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
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

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
        let access_token = token_pair.access_token.to_string();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let new_budget = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(
                2021,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            end_date: NaiveDate::from_ymd(
                2023,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
        };

        let create_budget_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&new_budget)
            .to_request();

        let create_budget_resp = test::call_service(&app, create_budget_req).await;
        let create_budget_res_body = String::from_utf8(
            actix_web::test::read_body(create_budget_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let budget_before_edit =
            serde_json::from_str::<OutputBudget>(create_budget_res_body.as_str()).unwrap();

        let edit_budget = InputEditBudget {
            id: budget_before_edit.id.clone(),
            name: format!("Test Budget {user_number} after edit"),
            description: new_budget.description.clone(),
            start_date: new_budget.start_date.clone(),
            end_date: NaiveDate::from_ymd(
                2024,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/edit")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&edit_budget)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let budget_after_edit = db::budget::get_budget_by_id(
            &db_thread_pool.get().unwrap(),
            budget_before_edit.id.clone(),
        )
        .unwrap();

        assert_eq!(&budget_after_edit.name, &edit_budget.name);
        assert_eq!(&budget_after_edit.description, &edit_budget.description);
        assert_eq!(&budget_after_edit.start_date, &edit_budget.start_date);
        assert_eq!(&budget_after_edit.end_date, &edit_budget.end_date);
    }

    #[actix_rt::test]
    async fn test_edit_budget_start_cannot_be_after_end() {
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
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

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
        let access_token = token_pair.access_token.to_string();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let new_budget = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(
                2021,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            end_date: NaiveDate::from_ymd(
                2023,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
        };

        let create_budget_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&new_budget)
            .to_request();

        let create_budget_resp = test::call_service(&app, create_budget_req).await;
        let create_budget_res_body = String::from_utf8(
            actix_web::test::read_body(create_budget_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let budget_before_edit =
            serde_json::from_str::<OutputBudget>(create_budget_res_body.as_str()).unwrap();

        let edit_budget = InputEditBudget {
            id: budget_before_edit.id.clone(),
            name: format!("Test Budget {user_number} after edit"),
            description: new_budget.description.clone(),
            start_date: new_budget.start_date.clone(),
            end_date: NaiveDate::from_ymd(
                2019,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/edit")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&edit_budget)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);

        let budget_after_edit = db::budget::get_budget_by_id(
            &db_thread_pool.get().unwrap(),
            budget_before_edit.id.clone(),
        )
        .unwrap();

        assert_eq!(&budget_after_edit.name, &new_budget.name);
        assert_eq!(&budget_after_edit.description, &new_budget.description);
        assert_eq!(&budget_after_edit.start_date, &new_budget.start_date);
        assert_eq!(&budget_after_edit.end_date, &new_budget.end_date);
    }

    #[actix_rt::test]
    async fn test_add_entry() {
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
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

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
        let access_token = token_pair.access_token.to_string();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let new_budget = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(
                2021,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            end_date: NaiveDate::from_ymd(
                2023,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
        };

        let create_budget_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&new_budget)
            .to_request();

        let create_budget_resp = test::call_service(&app, create_budget_req).await;
        let create_budget_res_body = String::from_utf8(
            actix_web::test::read_body(create_budget_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let budget = serde_json::from_str::<OutputBudget>(create_budget_res_body.as_str()).unwrap();

        let entry0 = InputEntry {
            budget_id: budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 0 for {user_number}")),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(7..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: None,
            category: None,
            note: None,
        };

        let new_entries = vec![entry0.clone(), entry1.clone()];

        let req0 = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&new_entries[0])
            .to_request();

        let resp0 = test::call_service(&app, req0).await;
        assert_eq!(resp0.status(), http::StatusCode::CREATED);

        let req1 = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&new_entries[1])
            .to_request();

        let resp1 = test::call_service(&app, req1).await;
        assert_eq!(resp1.status(), http::StatusCode::CREATED);

        let db_connection = db_thread_pool.get().unwrap();

        let budget_id = InputBudgetId {
            budget_id: budget.id,
        };

        let fetched_budget_req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(budget_id)
            .to_request();

        let fetched_budget_resp = test::call_service(&app, fetched_budget_req).await;
        let fetched_budget_res_body = String::from_utf8(
            actix_web::test::read_body(fetched_budget_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let budget =
            serde_json::from_str::<OutputBudget>(fetched_budget_res_body.as_str()).unwrap();

        let created_budget = budgets
            .find(budget.id)
            .first::<Budget>(&db_connection)
            .unwrap();

        let created_entries = Entry::belonging_to(&created_budget)
            .order(entry_fields::date.asc())
            .load::<Entry>(&db_connection)
            .unwrap();

        for i in 0..created_entries.len() {
            println!("\n\n{:#?}\n", created_entries);
            println!("{:#?}\n\n", new_entries);

            assert_eq!(created_entries[i].budget_id, new_entries[i].budget_id);
            assert_eq!(created_entries[i].amount_cents, new_entries[i].amount_cents);
            assert_eq!(created_entries[i].date, new_entries[i].date);
            assert_eq!(created_entries[i].name, new_entries[i].name);
            assert_eq!(created_entries[i].category, new_entries[i].category);
            assert_eq!(created_entries[i].note, new_entries[i].note);
        }
    }

    #[actix_rt::test]
    async fn test_get_budget() {
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
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

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
        let access_token = token_pair.access_token.to_string();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let new_budget = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(
                2021,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            end_date: NaiveDate::from_ymd(
                2023,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
        };

        let create_budget_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&new_budget)
            .to_request();

        let create_budget_resp = test::call_service(&app, create_budget_req).await;
        let create_budget_res_body = String::from_utf8(
            actix_web::test::read_body(create_budget_resp)
                .await
                .to_vec(),
        )
        .unwrap();
        let created_budget =
            serde_json::from_str::<OutputBudget>(create_budget_res_body.as_str()).unwrap();

        let entry0 = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 0 for {user_number}")),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(7..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: None,
            category: None,
            note: None,
        };

        let created_entries = vec![entry0.clone(), entry1.clone()];

        let entry0_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&created_entries[0])
            .to_request();

        test::call_service(&app, entry0_req).await;

        let entry1_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&created_entries[1])
            .to_request();

        test::call_service(&app, entry1_req).await;

        let input_budget_id = InputBudgetId {
            budget_id: created_budget.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(input_budget_id)
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(res).await.to_vec()).unwrap();
        let budget = serde_json::from_str::<OutputBudget>(res_body.as_str()).unwrap();

        assert_eq!(budget.id, created_budget.id);
        assert_eq!(budget.is_shared, created_budget.is_shared);
        assert_eq!(budget.is_private, created_budget.is_private);
        assert_eq!(budget.is_deleted, created_budget.is_deleted);
        assert_eq!(budget.name, created_budget.name);
        assert_eq!(budget.description, created_budget.description);
        assert_eq!(budget.start_date, created_budget.start_date);
        assert_eq!(budget.end_date, created_budget.end_date);

        assert!(budget.latest_entry_time > created_budget.latest_entry_time);

        assert_eq!(budget.modified_timestamp, created_budget.modified_timestamp);
        assert_eq!(budget.created_timestamp, created_budget.created_timestamp);

        assert!(!budget.categories.is_empty());
        assert_eq!(budget.categories.len(), created_budget.categories.len());

        for i in 0..budget_categories.len() {
            let fetched_cat = &budget.categories[i];
            let created_cat = &created_budget.categories[i];

            assert_eq!(fetched_cat.pk, created_cat.pk);
            assert_eq!(fetched_cat.budget_id, created_cat.budget_id);
            assert_eq!(fetched_cat.id, created_cat.id);
            assert_eq!(fetched_cat.name, created_cat.name);
            assert_eq!(fetched_cat.limit_cents, created_cat.limit_cents);
            assert_eq!(fetched_cat.color, created_cat.color);
        }

        for i in 0..created_entries.len() {
            assert_eq!(
                budget.entries[i].amount_cents,
                created_entries[i].amount_cents
            );
            assert_eq!(budget.entries[i].date, created_entries[i].date);
            assert_eq!(budget.entries[i].name, created_entries[i].name);
            assert_eq!(budget.entries[i].category, created_entries[i].category);
            assert_eq!(budget.entries[i].note, created_entries[i].note);
        }
    }

    #[actix_rt::test]
    async fn test_get_all_budgets_for_user() {
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
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

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
        let access_token = token_pair.access_token.to_string();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0.clone(), category1.clone()];

        let new_budget0 = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(
                2021,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            end_date: NaiveDate::from_ymd(
                2023,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
        };

        let create_budget0_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&new_budget0)
            .to_request();

        let create_budget0_resp = test::call_service(&app, create_budget0_req).await;
        let create_budget0_res_body = String::from_utf8(
            actix_web::test::read_body(create_budget0_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let created_budget0 =
            serde_json::from_str::<OutputBudget>(create_budget0_res_body.as_str()).unwrap();

        let new_budget1 = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            end_date: NaiveDate::from_ymd(
                2023,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
        };

        let create_budget1_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&new_budget1)
            .to_request();

        let create_budget1_resp = test::call_service(&app, create_budget1_req).await;
        let create_budget1_res_body = String::from_utf8(
            actix_web::test::read_body(create_budget1_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let created_budget1 =
            serde_json::from_str::<OutputBudget>(create_budget1_res_body.as_str()).unwrap();

        let created_budgets = vec![created_budget0.clone(), created_budget1.clone()];

        let entry0 = InputEntry {
            budget_id: created_budget0.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 0 for {user_number}")),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: created_budget0.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(7..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: None,
            category: None,
            note: None,
        };

        let entry2 = InputEntry {
            budget_id: created_budget1.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 2 for {user_number}")),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry3 = InputEntry {
            budget_id: created_budget1.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(7..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: None,
            category: None,
            note: None,
        };

        let created_entries = vec![
            vec![entry0.clone(), entry1.clone()],
            vec![entry2.clone(), entry3.clone()],
        ];

        let entry0_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry0)
            .to_request();

        test::call_service(&app, entry0_req).await;

        let entry1_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry1)
            .to_request();

        test::call_service(&app, entry1_req).await;

        let entry2_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry2)
            .to_request();

        test::call_service(&app, entry2_req).await;

        let entry3_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry3)
            .to_request();

        test::call_service(&app, entry3_req).await;

        let req = test::TestRequest::get()
            .uri("/api/budget/get_all")
            .insert_header(("authorization", format!("bearer {access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let output_budgets = serde_json::from_str::<Vec<OutputBudget>>(res_body.as_str()).unwrap();
        assert_eq!(output_budgets.len(), 2);

        for i in 0..output_budgets.len() {
            let budget = &output_budgets[i];
            let created_budget = &created_budgets[i];

            assert_eq!(budget.id, created_budget.id);
            assert_eq!(budget.is_shared, created_budget.is_shared);
            assert_eq!(budget.is_private, created_budget.is_private);
            assert_eq!(budget.is_deleted, created_budget.is_deleted);
            assert_eq!(budget.name, created_budget.name);
            assert_eq!(budget.description, created_budget.description);
            assert_eq!(budget.start_date, created_budget.start_date);
            assert_eq!(budget.end_date, created_budget.end_date);

            assert!(budget.latest_entry_time > created_budget.latest_entry_time);

            assert_eq!(budget.modified_timestamp, created_budget.modified_timestamp);
            assert_eq!(budget.created_timestamp, created_budget.created_timestamp);

            assert!(!budget.categories.is_empty());
            assert_eq!(budget.categories.len(), created_budget.categories.len());

            for j in 0..budget_categories.len() {
                let fetched_cat = &budget.categories[j];
                let created_cat = &created_budget.categories[j];

                assert_eq!(fetched_cat.pk, created_cat.pk);
                assert_eq!(fetched_cat.budget_id, created_cat.budget_id);
                assert_eq!(fetched_cat.id, created_cat.id);
                assert_eq!(fetched_cat.name, created_cat.name);
                assert_eq!(fetched_cat.limit_cents, created_cat.limit_cents);
                assert_eq!(fetched_cat.color, created_cat.color);
            }

            for j in 0..created_entries[i].len() {
                assert_eq!(
                    budget.entries[j].amount_cents,
                    created_entries[i][j].amount_cents
                );
                assert_eq!(budget.entries[j].date, created_entries[i][j].date);
                assert_eq!(budget.entries[j].name, created_entries[i][j].name);
                assert_eq!(budget.entries[j].category, created_entries[i][j].category);
                assert_eq!(budget.entries[j].note, created_entries[i][j].note);
            }
        }
    }

    #[actix_rt::test]
    async fn test_get_all_budgets_for_user_between_dates() {
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
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

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
        let access_token = token_pair.access_token.to_string();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0.clone(), category1.clone()];

        let too_early_budget = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(2022, 3, 14),
            end_date: NaiveDate::from_ymd(2022, 3, 30),
        };

        let create_too_early_budget_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&too_early_budget)
            .to_request();

        let create_too_early_budget_resp =
            test::call_service(&app, create_too_early_budget_req).await;
        let create_too_early_budget_res_body = String::from_utf8(
            actix_web::test::read_body(create_too_early_budget_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let created_too_early_budget =
            serde_json::from_str::<OutputBudget>(create_too_early_budget_res_body.as_str())
                .unwrap();

        let in_range_budget0 = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(2022, 3, 12),
            end_date: NaiveDate::from_ymd(2022, 4, 18),
        };

        let create_in_range_budget0_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&in_range_budget0)
            .to_request();

        let create_in_range_budget0_resp =
            test::call_service(&app, create_in_range_budget0_req).await;
        let create_in_range_budget0_res_body = String::from_utf8(
            actix_web::test::read_body(create_in_range_budget0_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let created_in_range_budget0 =
            serde_json::from_str::<OutputBudget>(create_in_range_budget0_res_body.as_str())
                .unwrap();

        let in_range_budget1 = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(2022, 4, 8),
            end_date: NaiveDate::from_ymd(2022, 4, 10),
        };

        let create_in_range_budget1_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&in_range_budget1)
            .to_request();

        let create_in_range_budget1_resp =
            test::call_service(&app, create_in_range_budget1_req).await;
        let create_in_range_budget1_res_body = String::from_utf8(
            actix_web::test::read_body(create_in_range_budget1_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let created_in_range_budget1 =
            serde_json::from_str::<OutputBudget>(create_in_range_budget1_res_body.as_str())
                .unwrap();

        let in_range_budget2 = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(2022, 4, 9),
            end_date: NaiveDate::from_ymd(2022, 5, 6),
        };

        let create_in_range_budget2_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&in_range_budget2)
            .to_request();

        let create_in_range_budget2_resp =
            test::call_service(&app, create_in_range_budget2_req).await;
        let create_in_range_budget2_res_body = String::from_utf8(
            actix_web::test::read_body(create_in_range_budget2_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let created_in_range_budget2 =
            serde_json::from_str::<OutputBudget>(create_in_range_budget2_res_body.as_str())
                .unwrap();

        let too_late_budget = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(2022, 4, 22),
            end_date: NaiveDate::from_ymd(2022, 4, 30),
        };

        let create_too_late_budget_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&too_late_budget)
            .to_request();

        let create_too_late_budget_resp =
            test::call_service(&app, create_too_late_budget_req).await;
        let create_too_late_budget_res_body = String::from_utf8(
            actix_web::test::read_body(create_too_late_budget_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let created_too_late_budget =
            serde_json::from_str::<OutputBudget>(create_too_late_budget_res_body.as_str()).unwrap();

        let in_range_budgets = vec![
            created_in_range_budget0.clone(),
            created_in_range_budget1.clone(),
            created_in_range_budget2.clone(),
        ];

        let entry0 = InputEntry {
            budget_id: created_too_early_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 0 for {user_number}")),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: created_too_early_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(7..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: None,
            category: None,
            note: None,
        };

        let entry2 = InputEntry {
            budget_id: created_in_range_budget0.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 2 for {user_number}")),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry3 = InputEntry {
            budget_id: created_in_range_budget0.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(7..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: None,
            category: None,
            note: None,
        };

        let entry4 = InputEntry {
            budget_id: created_in_range_budget1.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 2 for {user_number}")),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry5 = InputEntry {
            budget_id: created_in_range_budget1.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(7..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: None,
            category: None,
            note: None,
        };

        let entry6 = InputEntry {
            budget_id: created_in_range_budget2.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 2 for {user_number}")),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry7 = InputEntry {
            budget_id: created_in_range_budget2.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(7..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: None,
            category: None,
            note: None,
        };

        let entry8 = InputEntry {
            budget_id: created_too_late_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 2 for {user_number}")),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry9 = InputEntry {
            budget_id: created_too_late_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(7..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: None,
            category: None,
            note: None,
        };

        let in_range_budget_entries = vec![
            vec![entry2.clone(), entry3.clone()],
            vec![entry4.clone(), entry5.clone()],
            vec![entry6.clone(), entry7.clone()],
        ];

        let entry0_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry0)
            .to_request();

        test::call_service(&app, entry0_req).await;

        let entry1_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry1)
            .to_request();

        test::call_service(&app, entry1_req).await;

        let entry2_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry2)
            .to_request();

        test::call_service(&app, entry2_req).await;

        let entry3_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry3)
            .to_request();

        test::call_service(&app, entry3_req).await;

        let entry4_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry4)
            .to_request();

        test::call_service(&app, entry4_req).await;

        let entry5_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry5)
            .to_request();

        test::call_service(&app, entry5_req).await;

        let entry6_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry6)
            .to_request();

        test::call_service(&app, entry6_req).await;

        let entry7_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry7)
            .to_request();

        test::call_service(&app, entry7_req).await;

        let entry8_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry8)
            .to_request();

        test::call_service(&app, entry8_req).await;

        let entry9_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry9)
            .to_request();

        test::call_service(&app, entry9_req).await;

        let date_range = InputDateRange {
            start_date: NaiveDate::from_ymd(2022, 4, 6),
            end_date: NaiveDate::from_ymd(2022, 4, 12),
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/get_all_between_dates")
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&date_range)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let output_budgets = serde_json::from_str::<Vec<OutputBudget>>(res_body.as_str()).unwrap();
        assert_eq!(output_budgets.len(), 3);

        for i in 0..output_budgets.len() {
            let budget = &output_budgets[i];
            let created_budget = &in_range_budgets[i];

            assert_eq!(budget.id, created_budget.id);
            assert_eq!(budget.is_shared, created_budget.is_shared);
            assert_eq!(budget.is_private, created_budget.is_private);
            assert_eq!(budget.is_deleted, created_budget.is_deleted);
            assert_eq!(budget.name, created_budget.name);
            assert_eq!(budget.description, created_budget.description);
            assert_eq!(budget.start_date, created_budget.start_date);
            assert_eq!(budget.end_date, created_budget.end_date);

            assert!(budget.latest_entry_time > created_budget.latest_entry_time);

            assert_eq!(budget.modified_timestamp, created_budget.modified_timestamp);
            assert_eq!(budget.created_timestamp, created_budget.created_timestamp);

            assert!(!budget.categories.is_empty());
            assert_eq!(budget.categories.len(), created_budget.categories.len());

            for j in 0..budget_categories.len() {
                let fetched_cat = &budget.categories[j];
                let created_cat = &created_budget.categories[j];

                assert_eq!(fetched_cat.pk, created_cat.pk);
                assert_eq!(fetched_cat.budget_id, created_cat.budget_id);
                assert_eq!(fetched_cat.id, created_cat.id);
                assert_eq!(fetched_cat.name, created_cat.name);
                assert_eq!(fetched_cat.limit_cents, created_cat.limit_cents);
                assert_eq!(fetched_cat.color, created_cat.color);
            }

            for j in 0..in_range_budget_entries[i].len() {
                assert_eq!(
                    budget.entries[j].amount_cents,
                    in_range_budget_entries[i][j].amount_cents
                );
                assert_eq!(budget.entries[j].date, in_range_budget_entries[i][j].date);
                assert_eq!(budget.entries[j].name, in_range_budget_entries[i][j].name);
                assert_eq!(
                    budget.entries[j].category,
                    in_range_budget_entries[i][j].category
                );
                assert_eq!(budget.entries[j].note, in_range_budget_entries[i][j].note);
            }
        }
    }

    #[actix_rt::test]
    async fn test_cant_access_budget_for_another_user() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u32, _>(10_000_000..100_000_000);
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
        let user_id = jwt::read_claims(&signin_token.signin_token).unwrap().uid;

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
        let access_token = token_pair.access_token.to_string();

        let unauth_new_user = InputUser {
            email: format!("test_user_unauthorized{}@test.com", &user_number),
            password: String::from("tNmUV%9$khHK2TqOLw*%W"),
            first_name: format!("unauthTest-{}", &user_number),
            last_name: format!("UnauthUser-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        let create_unauth_user_res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&unauth_new_user).unwrap())
                .to_request(),
        )
        .await;

        let unauth_user_signin_token =
            test::read_body_json::<SigninToken, _>(create_unauth_user_res).await;
        let unauth_user_id = jwt::read_claims(&unauth_user_signin_token.signin_token)
            .unwrap()
            .uid;

        let unauth_user_otp = otp::generate_otp(unauth_user_id, current_time).unwrap();

        let unauth_user_token_and_otp = SigninTokenOtpPair {
            signin_token: unauth_user_signin_token.signin_token,
            otp: unauth_user_otp.to_string(),
        };

        let unauth_user_otp_req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&unauth_user_token_and_otp).unwrap())
            .to_request();

        let unauth_user_otp_res = test::call_service(&app, unauth_user_otp_req).await;
        let unauth_user_token_pair =
            actix_web::test::read_body_json::<TokenPair, _>(unauth_user_otp_res).await;
        let unauth_user_access_token = unauth_user_token_pair.access_token.to_string();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let new_budget = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(
                2021,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            end_date: NaiveDate::from_ymd(
                2023,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
        };

        let create_budget_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&new_budget)
            .to_request();

        let create_budget_resp = test::call_service(&app, create_budget_req).await;
        let create_budget_res_body = String::from_utf8(
            actix_web::test::read_body(create_budget_resp)
                .await
                .to_vec(),
        )
        .unwrap();
        let created_budget =
            serde_json::from_str::<OutputBudget>(create_budget_res_body.as_str()).unwrap();

        let entry0 = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 0 for {user_number}")),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(7..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: None,
            category: None,
            note: None,
        };

        let created_entries = vec![entry0.clone(), entry1.clone()];

        let entry0_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&created_entries[0])
            .to_request();

        test::call_service(&app, entry0_req).await;

        let entry1_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&created_entries[1])
            .to_request();

        test::call_service(&app, entry1_req).await;

        let input_budget_id = InputBudgetId {
            budget_id: created_budget.id,
        };

        let unauth_get_req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header((
                "authorization",
                format!("bearer {unauth_user_access_token}"),
            ))
            .set_json(input_budget_id)
            .to_request();

        let unauth_get_res = test::call_service(&app, unauth_get_req).await;
        assert_eq!(unauth_get_res.status(), http::StatusCode::NOT_FOUND);

        let unauth_get_res_body =
            String::from_utf8(actix_web::test::read_body(unauth_get_res).await.to_vec()).unwrap();
        let _unauth_get_parsed_body =
            serde_json::from_str::<OutputBudget>(unauth_get_res_body.as_str()).unwrap_err();

        let unauth_entry0_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header((
                "authorization",
                format!("bearer {unauth_user_access_token}"),
            ))
            .set_json(&created_entries[0])
            .to_request();

        let unauth_entry0_res = test::call_service(&app, unauth_entry0_req).await;
        assert_eq!(unauth_entry0_res.status(), http::StatusCode::NOT_FOUND);

        // Make sure the created budget hasn't changed

        let input_budget_id = InputBudgetId {
            budget_id: created_budget.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(input_budget_id)
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(res).await.to_vec()).unwrap();
        let budget = serde_json::from_str::<OutputBudget>(res_body.as_str()).unwrap();

        assert_eq!(budget.id, created_budget.id);
        assert_eq!(budget.is_shared, created_budget.is_shared);
        assert_eq!(budget.is_private, created_budget.is_private);
        assert_eq!(budget.is_deleted, created_budget.is_deleted);
        assert_eq!(budget.name, created_budget.name);
        assert_eq!(budget.description, created_budget.description);
        assert_eq!(budget.start_date, created_budget.start_date);
        assert_eq!(budget.end_date, created_budget.end_date);

        assert!(budget.latest_entry_time > created_budget.latest_entry_time);

        assert_eq!(budget.modified_timestamp, created_budget.modified_timestamp);
        assert_eq!(budget.created_timestamp, created_budget.created_timestamp);

        assert!(!budget.categories.is_empty());
        assert_eq!(budget.categories.len(), created_budget.categories.len());

        for i in 0..budget_categories.len() {
            let fetched_cat = &budget.categories[i];
            let created_cat = &created_budget.categories[i];

            assert_eq!(fetched_cat.pk, created_cat.pk);
            assert_eq!(fetched_cat.budget_id, created_cat.budget_id);
            assert_eq!(fetched_cat.id, created_cat.id);
            assert_eq!(fetched_cat.name, created_cat.name);
            assert_eq!(fetched_cat.limit_cents, created_cat.limit_cents);
            assert_eq!(fetched_cat.color, created_cat.color);
        }

        for i in 0..created_entries.len() {
            assert_eq!(
                budget.entries[i].amount_cents,
                created_entries[i].amount_cents
            );
            assert_eq!(budget.entries[i].date, created_entries[i].date);
            assert_eq!(budget.entries[i].name, created_entries[i].name);
            assert_eq!(budget.entries[i].category, created_entries[i].category);
            assert_eq!(budget.entries[i].note, created_entries[i].note);
        }
    }
}
