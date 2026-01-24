use actix_web::web::*;

use crate::handlers::error_reporting;

use super::RateLimiters;

pub fn configure(cfg: &mut ServiceConfig, limiters: RateLimiters) {
    cfg.service(
        resource("/client-errors")
            .route(
                get()
                    .to(error_reporting::get_client_errors)
                    .wrap(limiters.read_circuit_breaker.clone()),
            )
            .route(
                post()
                    .to(error_reporting::report_error)
                    .wrap(limiters.read_circuit_breaker),
            ),
    );
}
