use actix_web::web::*;

use crate::handlers::health;

pub fn configure(cfg: &mut ServiceConfig) {
    cfg.service(
        scope("")
            .route("/heartbeat", get().to(health::heartbeat))
            .route("/health", get().to(health::health)),
    );
}
