use actix_web::{web, HttpResponse};
use log::error;
use uuid::Uuid;

use crate::definitions::DbThreadPool;
use crate::handlers::error::ServerError;
use crate::handlers::request_io::{
    InputBudget, InputBudgetId, InputBudgetShareEventId, InputDateRange, InputEditBudget,
    InputEntry, OutputBudget, UserInvitationToBudget,
};
use crate::middleware;
use crate::utils::db;

pub async fn get(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    budget_id: web::Json<InputBudgetId>,
) -> Result<HttpResponse, ServerError> {
    let budget = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        db::budget::get_budget_by_id(&db_connection, budget_id.budget_id, auth_user_claims.0.uid)
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
                return Err(ServerError::NotFound(Some("No budget with provided ID")));
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

    match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::budget::edit_budget(&db_connection, &budget_data, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(count) => {
            if count == 0 {
                Err(ServerError::NotFound(Some(
                    "Budget not found or no changes were made",
                )))
            } else {
                Ok(HttpResponse::Ok().finish())
            }
        }
        Err(e) => {
            error!("{}", e);
            Err(ServerError::DatabaseTransactionError(Some(
                "Failed to edit budget",
            )))
        }
    }
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

pub async fn invite_user(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    invitation_info: web::Json<UserInvitationToBudget>,
) -> Result<HttpResponse, ServerError> {
    let inviting_user_id = auth_user_claims.0.uid.clone();
    ensure_user_in_budget(
        db_thread_pool.clone(),
        inviting_user_id,
        invitation_info.budget_id.clone(),
    )
    .await?;

    match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::budget::invite_user(
            &db_connection,
            invitation_info.budget_id,
            invitation_info.invitee_user_id,
            inviting_user_id,
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
                    "Failed to share budget",
                )));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn retract_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    invitation_id: web::Json<InputBudgetShareEventId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::budget::delete_invitation(
            &db_connection,
            invitation_id.share_event_id,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(count) => {
            if count == 0 {
                return Err(ServerError::NotFound(Some("No share event belonging to user with provided ID")));
            }
        },
        Err(e) => match e {
            diesel::result::Error::NotFound => {
                return Err(ServerError::NotFound(Some(
                    "No share event with provided ID",
                )));
            },
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to delete invitation",
                )));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn accept_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    invitation_id: web::Json<InputBudgetShareEventId>,
) -> Result<HttpResponse, ServerError> {
    let db_thread_pool_ref = db_thread_pool.clone();
    let share_event_id = invitation_id.share_event_id;
    
    let rows_affected_count = match web::block(move || {
        let db_connection = db_thread_pool_ref
            .get()
            .expect("Failed to access database thread pool");

        db::budget::mark_invitation_accepted(
            &db_connection,
            share_event_id,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(count) => count,
        Err(e) => match e {
            diesel::result::Error::NotFound => {
                return Err(ServerError::NotFound(Some(
                    "No share event with provided ID",
                )));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to accept invitation",
                )));
            }
        },
    };

    if rows_affected_count == 0 {
        return Err(ServerError::UserUnauthorized(Some("User not authorized to accept invitation")));
    }

    match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::budget::add_user(
            &db_connection,
            invitation_id.budget_id,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => {
            error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(
                "Failed to accept invitation",
            )));
        },
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn decline_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    invitation_id: web::Json<InputBudgetShareEventId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::budget::mark_invitation_declined(
            &db_connection,
            invitation_id.share_event_id,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(count) => {
            if count == 0 {
                return Err(ServerError::UserUnauthorized(Some("User not authorized to decline invitation")));
            }
        },
        Err(e) => match e {
            diesel::result::Error::NotFound => {
                return Err(ServerError::NotFound(Some(
                    "No share event with provided ID",
                )));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to decline invitation",
                )));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn get_all_pending_invitations_for_user(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let invites = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::budget::get_all_pending_invitations_for_user(&db_connection, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(invites) => invites,
        Err(e) => match e {
            diesel::result::Error::NotFound => {
                return Err(ServerError::NotFound(Some("No share events for user")));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to find invitations",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().json(invites))
}

pub async fn get_all_pending_invitations_made_by_user(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let invites = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::budget::get_all_pending_invitations_made_by_user(&db_connection, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(invites) => invites,
        Err(e) => match e {
            diesel::result::Error::NotFound => {
                return Err(ServerError::NotFound(Some("No share events made by user")));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to find invitations",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().json(invites))
}

pub async fn get_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    invitation_id: web::Json<InputBudgetShareEventId>,
) -> Result<HttpResponse, ServerError> {
    let invite = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::budget::get_invitation(
            &db_connection,
            invitation_id.share_event_id,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            diesel::result::Error::NotFound => {
                return Err(ServerError::NotFound(Some("Share event not found")));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to find invitations",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().json(invite))
}

pub async fn remove_budget(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    budget_id: web::Json<Uuid>,
) -> Result<HttpResponse, ServerError> {
    let db_thread_pool_copy = db_thread_pool.clone();
    let db_thread_pool_second_copy = db_thread_pool.clone();

    match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        db::budget::remove_user(&db_connection, budget_id.0, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            diesel::result::Error::NotFound => {
                return Err(ServerError::NotFound(Some(
                    "User budget association not found",
                )));
            }
            _ => {
                error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(
                    "Failed to remove association with budget",
                )));
            }
        },
    }

    // TODO: Perhaps user shouldn't have to wait for this (make it non-blocking)
    let remaining_users_in_budget = match web::block(move || {
        let db_connection = db_thread_pool_copy
            .get()
            .expect("Failed to access database thread pool");

        db::budget::count_users_remaining_in_budget(&db_connection, budget_id.0)
    })
    .await?
    {
        Ok(c) => c,
        Err(e) => match e {
            _ => {
                error!(
                    "Failed to see how many users left in budget with ID '{}': {}",
                    budget_id.0, e
                );
                10
            }
        },
    };

    if remaining_users_in_budget == 0 {
        match web::block(move || {
            let db_connection = db_thread_pool_second_copy
                .get()
                .expect("Failed to access database thread pool");

            db::budget::delete_budget(&db_connection, budget_id.0)
        })
        .await?
        {
            Ok(_) => (),
            Err(e) => match e {
                _ => error!("Failed to delete budget with ID '{}': {}", budget_id.0, e),
            },
        };
    }

    Ok(HttpResponse::Ok().finish())
}

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
    use uuid::Uuid;

    use crate::definitions::*;
    use crate::env;
    use crate::handlers::request_io::{
        InputBudget, InputBudgetId, InputCategory, InputDateRange, InputEditBudget, InputEntry,
        InputUser, OutputBudget, SigninToken, SigninTokenOtpPair, TokenPair, UserInvitationToBudget,
        InputBudgetShareEventId,
    };
    use crate::models::budget::Budget;
    use crate::models::budget_share_event::BudgetShareEvent;
    use crate::models::category::Category;
    use crate::models::entry::Entry;
    use crate::schema::budgets as budget_fields;
    use crate::schema::budgets::dsl::budgets;
    use crate::schema::budget_share_events as budget_share_event_fields;
    use crate::schema::budget_share_events::dsl::budget_share_events;
    use crate::schema::entries as entry_fields;
    use crate::services;
    use crate::utils::auth_token::TokenClaims;
    use crate::utils::{db, otp};

    pub struct UserAndBudgetWithAuthTokens {
        budget: OutputBudget,
        user_id: Uuid,
        token_pair: TokenPair,
    }

    pub async fn create_user_and_budget_and_sign_in(
        db_thread_pool: DbThreadPool,
    ) -> UserAndBudgetWithAuthTokens {
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

        let create_budget_res = test::call_service(&app, create_budget_req).await;
        let create_budget_res_body =
            String::from_utf8(actix_web::test::read_body(create_budget_res).await.to_vec())
                .unwrap();

        let budget = serde_json::from_str::<OutputBudget>(create_budget_res_body.as_str()).unwrap();

        UserAndBudgetWithAuthTokens {
            budget,
            user_id,
            token_pair,
        }
    }

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

        let created_user_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user_id = created_user_and_budget.user_id;
        let budget_before_edit = created_user_and_budget.budget.clone();
        let access_token = created_user_and_budget.token_pair.access_token.clone();

        let edit_budget = InputEditBudget {
            id: budget_before_edit.id.clone(),
            name: format!("Test Budget user after edit"),
            description: budget_before_edit.description.clone(),
            start_date: budget_before_edit.start_date.clone(),
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
            created_user_id,
        )
        .unwrap();

        assert_eq!(&budget_after_edit.name, &edit_budget.name);
        assert_eq!(&budget_after_edit.description, &edit_budget.description);
        assert_eq!(&budget_after_edit.start_date, &edit_budget.start_date);
        assert_eq!(&budget_after_edit.end_date, &edit_budget.end_date);
    }

    #[actix_rt::test]
    async fn test_cannot_edit_budget_of_another_user() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user_and_budget1 =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user1_id = created_user_and_budget1.user_id;

        let created_user_and_budget2 =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;

        let budget_before_edit = created_user_and_budget1.budget.clone();
        let access_token = created_user_and_budget2.token_pair.access_token.clone();

        let edit_budget = InputEditBudget {
            id: budget_before_edit.id.clone(),
            name: format!("Test Budget user after edit"),
            description: budget_before_edit.description.clone(),
            start_date: budget_before_edit.start_date.clone(),
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
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let budget_after_edit = db::budget::get_budget_by_id(
            &db_thread_pool.get().unwrap(),
            budget_before_edit.id.clone(),
            created_user1_id,
        )
        .unwrap();

        assert_eq!(&budget_after_edit.name, &budget_before_edit.name);
        assert_eq!(
            &budget_after_edit.description,
            &budget_before_edit.description
        );
        assert_eq!(
            &budget_after_edit.start_date,
            &budget_before_edit.start_date
        );
        assert_eq!(&budget_after_edit.end_date, &budget_before_edit.end_date);
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

        let created_user_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user_id = created_user_and_budget.user_id;
        let budget_before_edit = created_user_and_budget.budget.clone();
        let access_token = created_user_and_budget.token_pair.access_token.clone();

        let edit_budget = InputEditBudget {
            id: budget_before_edit.id.clone(),
            name: format!("Test Budget user after edit"),
            description: budget_before_edit.description.clone(),
            start_date: budget_before_edit.start_date.clone(),
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
            created_user_id,
        )
        .unwrap();

        assert_eq!(&budget_after_edit.name, &budget_before_edit.name);
        assert_eq!(
            &budget_after_edit.description,
            &budget_before_edit.description
        );
        assert_eq!(
            &budget_after_edit.start_date,
            &budget_before_edit.start_date
        );
        assert_eq!(&budget_after_edit.end_date, &budget_before_edit.end_date);
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

        let created_user_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let budget = created_user_and_budget.budget.clone();
        let access_token = created_user_and_budget.token_pair.access_token.clone();

        let entry0 = InputEntry {
            budget_id: budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 0 for user")),
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
            assert_eq!(created_entries[i].budget_id, new_entries[i].budget_id);
            assert_eq!(created_entries[i].amount_cents, new_entries[i].amount_cents);
            assert_eq!(created_entries[i].date, new_entries[i].date);
            assert_eq!(created_entries[i].name, new_entries[i].name);
            assert_eq!(created_entries[i].category, new_entries[i].category);
            assert_eq!(created_entries[i].note, new_entries[i].note);
        }
    }

    #[actix_rt::test]
    async fn test_invite_user_and_accept() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user1_id = created_user1_and_budget.user_id;
        let created_user1_budget = created_user1_and_budget.budget;

        let created_user2_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user2_id = created_user2_and_budget.user_id;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();

        let invitation_info = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let instant_before_share = chrono::Utc::now().naive_utc();

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&db_connection)
            .unwrap();

        let instant_after_share = chrono::Utc::now().naive_utc();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sharer_user_id, created_user1_id);
        assert_eq!(share_events[0].accepted, false);

        assert!(share_events[0].accepted_declined_timestamp.is_none());
        assert!(share_events[0].share_timestamp > instant_before_share);
        assert!(share_events[0].share_timestamp < instant_after_share);

        let input_budget_id = InputBudgetId {
            budget_id: created_user1_budget.id,
        };
        
        let invite_id = InputBudgetShareEventId {
            share_event_id: share_events[0].id,
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/accept_invitation")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&invite_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sharer_user_id, created_user1_id);
        assert_eq!(share_events[0].accepted, true);

        assert!(share_events[0].accepted_declined_timestamp.is_some());
        assert!(share_events[0].share_timestamp > instant_before_share);
        assert!(share_events[0].share_timestamp < instant_after_share);

        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&input_budget_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&input_budget_id)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_rt::test]
    async fn test_cannot_accept_invites_for_another_user() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user1_id = created_user1_and_budget.user_id;
        let created_user1_budget = created_user1_and_budget.budget;

        let created_user2_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user2_id = created_user2_and_budget.user_id;

        let created_user3_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();
        let user3_access_token = created_user3_and_budget.token_pair.access_token.clone();

        let invitation_info = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let instant_before_share = chrono::Utc::now().naive_utc();

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&db_connection)
            .unwrap();

        let instant_after_share = chrono::Utc::now().naive_utc();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sharer_user_id, created_user1_id);
        assert_eq!(share_events[0].accepted, false);

        assert!(share_events[0].accepted_declined_timestamp.is_none());
        assert!(share_events[0].share_timestamp > instant_before_share);
        assert!(share_events[0].share_timestamp < instant_after_share);

        let input_budget_id = InputBudgetId {
            budget_id: created_user1_budget.id,
        };
        
        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&input_budget_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .set_json(&input_budget_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let invite_id = InputBudgetShareEventId {
            share_event_id: share_events[0].id,
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/accept_invitation")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invite_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        let req = test::TestRequest::post()
            .uri("/api/budget/accept_invitation")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .set_json(&invite_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        let req = test::TestRequest::post()
            .uri("/api/budget/accept_invitation")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&invite_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sharer_user_id, created_user1_id);
        assert_eq!(share_events[0].accepted, true);

        assert!(share_events[0].accepted_declined_timestamp.is_some());
        assert!(share_events[0].share_timestamp > instant_before_share);
        assert!(share_events[0].share_timestamp < instant_after_share);

        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&input_budget_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&input_budget_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .set_json(&input_budget_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    }

    #[actix_rt::test]
    async fn test_invite_user_and_decline() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();
        
        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user1_id = created_user1_and_budget.user_id;
        let created_user1_budget = created_user1_and_budget.budget;

        let created_user2_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user2_id = created_user2_and_budget.user_id;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();

        let invitation_info = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let instant_before_share = chrono::Utc::now().naive_utc();

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&db_connection)
            .unwrap();

        let instant_after_share = chrono::Utc::now().naive_utc();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sharer_user_id, created_user1_id);
        assert_eq!(share_events[0].accepted, false);

        assert!(share_events[0].accepted_declined_timestamp.is_none());
        assert!(share_events[0].share_timestamp > instant_before_share);
        assert!(share_events[0].share_timestamp < instant_after_share);

        let input_budget_id = InputBudgetId {
            budget_id: created_user1_budget.id,
        };
        
        let invite_id = InputBudgetShareEventId {
            share_event_id: share_events[0].id,
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/decline_invitation")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&invite_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sharer_user_id, created_user1_id);
        assert_eq!(share_events[0].accepted, false);

        assert!(share_events[0].accepted_declined_timestamp.is_some());
        assert!(share_events[0].share_timestamp > instant_before_share);
        assert!(share_events[0].share_timestamp < instant_after_share);

        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&input_budget_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&input_budget_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_rt::test]
    async fn test_cannot_decline_invites_for_another_user() {
                let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user1_id = created_user1_and_budget.user_id;
        let created_user1_budget = created_user1_and_budget.budget;

        let created_user2_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user2_id = created_user2_and_budget.user_id;

        let created_user3_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();
        let user3_access_token = created_user3_and_budget.token_pair.access_token.clone();

        let invitation_info = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let instant_before_share = chrono::Utc::now().naive_utc();

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&db_connection)
            .unwrap();

        let instant_after_share = chrono::Utc::now().naive_utc();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sharer_user_id, created_user1_id);
        assert_eq!(share_events[0].accepted, false);

        assert!(share_events[0].accepted_declined_timestamp.is_none());
        assert!(share_events[0].share_timestamp > instant_before_share);
        assert!(share_events[0].share_timestamp < instant_after_share);

        let input_budget_id = InputBudgetId {
            budget_id: created_user1_budget.id,
        };
        
        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&input_budget_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .set_json(&input_budget_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let invite_id = InputBudgetShareEventId {
            share_event_id: share_events[0].id,
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/decline_invitation")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invite_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        let req = test::TestRequest::post()
            .uri("/api/budget/decline_invitation")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .set_json(&invite_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        let req = test::TestRequest::post()
            .uri("/api/budget/decline_invitation")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&invite_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sharer_user_id, created_user1_id);
        assert_eq!(share_events[0].accepted, false);

        assert!(share_events[0].accepted_declined_timestamp.is_some());
        assert!(share_events[0].share_timestamp > instant_before_share);
        assert!(share_events[0].share_timestamp < instant_after_share);

        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&input_budget_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&input_budget_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::post()
            .uri("/api/budget/get")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .set_json(&input_budget_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    }
    
    #[actix_rt::test]
    async fn test_retract_invitation() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();
        
        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user1_budget = created_user1_and_budget.budget;

        let created_user2_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user2_id = created_user2_and_budget.user_id;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();

        let invitation_info = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);

        let invite_id = InputBudgetShareEventId {
            share_event_id: share_events[0].id,
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/retract_invitation")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invite_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 0);
    }

    #[actix_rt::test]
    async fn test_cannot_retract_invites_made_by_another_user() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();
        
        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user1_budget = created_user1_and_budget.budget;

        let created_user2_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user2_id = created_user2_and_budget.user_id;

        let created_user3_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();
        let user3_access_token = created_user3_and_budget.token_pair.access_token.clone();

        let invitation_info = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);

        let invite_id = InputBudgetShareEventId {
            share_event_id: share_events[0].id,
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/retract_invitation")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&invite_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::post()
            .uri("/api/budget/retract_invitation")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .set_json(&invite_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);

        let req = test::TestRequest::post()
            .uri("/api/budget/retract_invitation")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invite_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 0);
    }

    #[actix_rt::test]
    async fn test_get_all_invitations_for_user() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user1_budget1 = created_user1_and_budget.budget;
        let created_user1_id = created_user1_and_budget.user_id;
        
        let created_user2_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user2_id = created_user2_and_budget.user_id;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category for user1_budget2"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category user1_budget2"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let new_budget = InputBudget {
            name: format!("Test Budget #2"),
            description: Some(format!(
                "This is a description of Test Budget #2.",
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
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&new_budget)
            .to_request();

        let create_budget_resp = test::call_service(&app, create_budget_req).await;
        let create_budget_resp_body =
            String::from_utf8(actix_web::test::read_body(create_budget_resp).await.to_vec())
                .unwrap();

        let created_user1_budget2 = serde_json::from_str::<OutputBudget>(create_budget_resp_body.as_str()).unwrap();

        let invitation_info_budget1 = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget1.id,
        };

        let invitation_info_budget2 = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget2.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info_budget1)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info_budget2)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::post()
            .uri("/api/budget/get_all_pending_invitations_for_user")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&created_user2_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();

        println!("{resp_body}");
        
        let invitations = serde_json::from_str::<Vec<BudgetShareEvent>>(resp_body.as_str()).unwrap();
        
        assert_eq!(invitations.len(), 2);

        let budget1_invitation = &invitations[0];
        let budget2_invitation = &invitations[1];

        assert_eq!(budget1_invitation.recipient_user_id, created_user2_id);
        assert_eq!(budget1_invitation.sharer_user_id, created_user1_id);
        assert_eq!(budget1_invitation.budget_id, created_user1_budget1.id);
        assert_eq!(budget1_invitation.accepted, false);
        assert!(budget1_invitation.accepted_declined_timestamp.is_none());

        assert_eq!(budget2_invitation.recipient_user_id, created_user2_id);
        assert_eq!(budget2_invitation.sharer_user_id, created_user1_id);
        assert_eq!(budget2_invitation.budget_id, created_user1_budget2.id);
        assert_eq!(budget2_invitation.accepted, false);
        assert!(budget2_invitation.accepted_declined_timestamp.is_none());
    }

    #[actix_rt::test]
    async fn test_get_all_invitations_made_by_user() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user1_budget1 = created_user1_and_budget.budget;
        let created_user1_id = created_user1_and_budget.user_id;
        
        let created_user2_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_user2_id = created_user2_and_budget.user_id;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category for user1_budget2"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category user1_budget2"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let new_budget = InputBudget {
            name: format!("Test Budget #2"),
            description: Some(format!(
                "This is a description of Test Budget #2.",
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
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&new_budget)
            .to_request();

        let create_budget_resp = test::call_service(&app, create_budget_req).await;
        let create_budget_resp_body =
            String::from_utf8(actix_web::test::read_body(create_budget_resp).await.to_vec())
                .unwrap();

        let created_user1_budget2 = serde_json::from_str::<OutputBudget>(create_budget_resp_body.as_str()).unwrap();

        let invitation_info_budget1 = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget1.id,
        };

        let invitation_info_budget2 = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget2.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info_budget1)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info_budget2)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::post()
            .uri("/api/budget/get_all_pending_invitations_made_by_user")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&created_user2_id)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();

        println!("{resp_body}");
        
        let invitations = serde_json::from_str::<Vec<BudgetShareEvent>>(resp_body.as_str()).unwrap();
        
        assert_eq!(invitations.len(), 2);

        let budget1_invitation = &invitations[0];
        let budget2_invitation = &invitations[1];

        assert_eq!(budget1_invitation.recipient_user_id, created_user2_id);
        assert_eq!(budget1_invitation.sharer_user_id, created_user1_id);
        assert_eq!(budget1_invitation.budget_id, created_user1_budget1.id);
        assert_eq!(budget1_invitation.accepted, false);
        assert!(budget1_invitation.accepted_declined_timestamp.is_none());

        assert_eq!(budget2_invitation.recipient_user_id, created_user2_id);
        assert_eq!(budget2_invitation.sharer_user_id, created_user1_id);
        assert_eq!(budget2_invitation.budget_id, created_user1_budget2.id);
        assert_eq!(budget2_invitation.accepted, false);
        assert!(budget2_invitation.accepted_declined_timestamp.is_none());
    }

    // #[actix_rt::test]
    // async fn test_get_invitation() {
    //     // TODO: Test that both the inviter and the invitee can get the invitation, but not another user
    //     todo!();
    // }

    // #[actix_rt::test]
    // async fn test_remove_user() {
    //     todo!();
    // }

    // #[actix_rt::test]
    // async fn test_remove_last_user_deletes_budget() {
    //     todo!();
    // }

    #[actix_rt::test]
    async fn test_get_budget() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(db_thread_pool.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_budget = created_user_and_budget.budget.clone();
        let access_token = created_user_and_budget.token_pair.access_token.clone();
        let budget_categories = created_budget.categories.clone();

        let entry0 = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 0 for user")),
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

        let created_user_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_budget0 = created_user_and_budget.budget.clone();
        let access_token = created_user_and_budget.token_pair.access_token.clone();

        let mut budget_categories = Vec::new();
        budget_categories.push(InputCategory {
            id: created_budget0.categories[0].id,
            name: created_budget0.categories[0].name.clone(),
            limit_cents: created_budget0.categories[0].limit_cents,
            color: created_budget0.categories[0].color.clone(),
        });

        budget_categories.push(InputCategory {
            id: created_budget0.categories[1].id,
            name: created_budget0.categories[1].name.clone(),
            limit_cents: created_budget0.categories[1].limit_cents,
            color: created_budget0.categories[1].color.clone(),
        });

        let new_budget1 = InputBudget {
            name: format!("Test Budget user"),
            description: Some(format!("This is a description of Test Budget user.",)),
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
            name: Some(format!("Test Entry 0 for user")),
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
            name: Some(format!("Test Entry 2 for user")),
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

        let created_user_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_budget = created_user_and_budget.budget.clone();
        let access_token = created_user_and_budget.token_pair.access_token.clone();

        diesel::delete(budgets.find(created_budget.id))
            .execute(&db_thread_pool.get().unwrap())
            .unwrap();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category user"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category user"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0.clone(), category1.clone()];

        let too_early_budget = InputBudget {
            name: format!("Test Budget user"),
            description: Some(format!("This is a description of Test Budget user.",)),
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
            name: format!("Test Budget user"),
            description: Some(format!("This is a description of Test Budget user.",)),
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
            name: format!("Test Budget user"),
            description: Some(format!("This is a description of Test Budget user.",)),
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
            name: format!("Test Budget user"),
            description: Some(format!("This is a description of Test Budget user.",)),
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
            name: format!("Test Budget user"),
            description: Some(format!("This is a description of Test Budget user.",)),
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
            name: Some(format!("Test Entry 0 for user")),
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
            name: Some(format!("Test Entry 2 for user")),
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
            name: Some(format!("Test Entry 2 for user")),
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
            name: Some(format!("Test Entry 2 for user")),
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
            name: Some(format!("Test Entry 2 for user")),
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

        let created_user_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let created_budget = created_user_and_budget.budget.clone();
        let access_token = created_user_and_budget.token_pair.access_token.clone();

        let mut budget_categories = Vec::new();
        budget_categories.push(InputCategory {
            id: created_budget.categories[0].id,
            name: created_budget.categories[0].name.clone(),
            limit_cents: created_budget.categories[0].limit_cents,
            color: created_budget.categories[0].color.clone(),
        });

        budget_categories.push(InputCategory {
            id: created_budget.categories[1].id,
            name: created_budget.categories[1].name.clone(),
            limit_cents: created_budget.categories[1].limit_cents,
            color: created_budget.categories[1].color.clone(),
        });

        let created_unauth_user_and_budget =
            create_user_and_budget_and_sign_in(db_thread_pool.clone()).await;
        let unauth_user_access_token = created_unauth_user_and_budget
            .token_pair
            .access_token
            .clone();

        let entry0 = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 0 for user")),
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
