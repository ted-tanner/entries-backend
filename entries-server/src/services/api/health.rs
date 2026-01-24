use actix_web::web::*;

use crate::handlers::health;

use super::RateLimiters;

pub fn configure(cfg: &mut ServiceConfig, limiters: RateLimiters) {
    cfg.route("/heartbeat", get().to(health::heartbeat)).route(
        "/health",
        get()
            .to(health::health)
            .wrap(limiters.read_fair_use)
            .wrap(limiters.read_circuit_breaker),
    );
}
