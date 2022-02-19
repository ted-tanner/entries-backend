use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/budget")
            .route("/get", web::get().to(handlers::budget::get))
            .route("/get_all", web::post().to(handlers::budget::get_all))
            .route(
                "/get_all_between_dates",
                web::post().to(handlers::budget::get_all_between_dates),
            )
            .route("/create", web::post().to(handlers::budget::create))
            .route("/add_entry", web::post().to(handlers::budget::add_entry)),
    );
}
