use actix_web::web::*;

use crate::handlers::error_reporting;

pub fn configure(cfg: &mut ServiceConfig) {
    cfg.service(
        resource("/client-errors")
            .route(get().to(error_reporting::get_client_errors))
            .route(post().to(error_reporting::report_error)),
    );
}
