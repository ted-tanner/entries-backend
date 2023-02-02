use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/tombstone")
            .route(
                "/check_tombstone_exists",
                web::put().to(handlers::tombstone::check_tombstone_exists),
            )
            .route(
                "/get_tombstones_since",
                web::put().to(handlers::tombstone::get_tombstones_since),
            ),
    );
}
