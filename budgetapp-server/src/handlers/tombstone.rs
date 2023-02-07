use actix_web::{web, HttpResponse};
use budgetapp_utils::request_io::{
    InputTime, InputTombstoneId, OutputTombstone, OutputTombstoneDoesExist,
};
use budgetapp_utils::{db, db::DaoError, db::DbThreadPool};

use crate::handlers::error::ServerError;
use crate::middleware::auth::AuthorizedUserClaims;

pub async fn check_tombstone_exists(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    item_id: web::Json<InputTombstoneId>,
) -> Result<HttpResponse, ServerError> {
    let does_exist = match web::block(move || {
        let mut tombstone_dao = db::tombstone::Dao::new(&db_thread_pool);
        tombstone_dao.check_tombstone_exists(item_id.item_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(exists) => exists,
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to check existence of tombstone",
            ))));
        }
    };

    Ok(HttpResponse::Ok().json(OutputTombstoneDoesExist { does_exist }))
}

pub async fn get_tombstones_since(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    from_time: web::Json<InputTime>,
) -> Result<HttpResponse, ServerError> {
    let tombstones = match web::block(move || {
        let mut tombstone_dao = db::tombstone::Dao::new(&db_thread_pool);
        tombstone_dao.get_tombstones_since(from_time.time, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(t) => t,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Ok(HttpResponse::Ok().json(Vec::<OutputTombstone>::new()));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to update category",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().json(tombstones))
}
