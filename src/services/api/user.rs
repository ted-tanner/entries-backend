use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .route("/get", web::get().to(handlers::user::get))
            .route("/create", web::post().to(handlers::user::create))
            .route("/edit", web::post().to(handlers::user::edit))
            .route(
                "/change_password",
                web::post().to(handlers::user::change_password),
            ),
    );
}
