use actix_web::web;

use crate::handlers::index;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .route("/", web::get().to(index::get::index))
            .route("/heartbeat", web::get().to(index::get::heartbeat)),
    );
}
