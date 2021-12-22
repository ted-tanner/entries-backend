use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .route("/get", web::get().to(handlers::user::get))
            .route("/create", web::post().to(handlers::user::create)),
    );
}
