use actix_web::web::*;

use crate::handlers::index;

pub fn configure(cfg: &mut ServiceConfig) {
    cfg.service(
        scope("")
            .route("/", get().to(index::get::index))
            .route("/heartbeat", get().to(index::get::heartbeat)),
    );
}
