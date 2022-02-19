use actix_web::{web, HttpResponse};
use log::error;

use crate::definitions::DbThreadPool;
use crate::handlers::error::ServerError;
use crate::handlers::request_io::{InputBudget, InputBudgetId, InputDateRange, InputEntry, OutputBudget};
use crate::middleware;
use crate::utils::db;

pub async fn get(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    budget_id: web::Json<InputBudgetId>,
) -> Result<HttpResponse, ServerError> {
    let db_connection = db_thread_pool
        .get()
        .expect("Failed to access database thread pool");

    let budget_id_clone = budget_id.budget_id.clone();

    let is_user_in_budget = match web::block(move || {
        db::budget::check_user_in_budget(&db_connection, &auth_user_claims.0.uid, &budget_id_clone)
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

    let budget = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        db::budget::get_budget_by_id(&db_connection, &budget_id.budget_id)
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
        db::budget::get_all_budgets_for_user(&db_connection, &auth_user_claims.0.uid)
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
            &auth_user_claims.0.uid,
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
        db::budget::create_budget(
            &db_connection,
	    &budget_data,
            &auth_user_claims.0.uid,
        )
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

    Ok(HttpResponse::Ok().json(new_budget))
}

pub async fn add_entry(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    entry_data: web::Json<InputEntry>,
) -> Result<HttpResponse, ServerError> {
    let new_entry = match web::block(move || {
        let db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");
        db::budget::create_entry(
            &db_connection,
	    &entry_data,
            &auth_user_claims.0.uid,
        )
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

    Ok(HttpResponse::Ok().json(new_entry))
}

