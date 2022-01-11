use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/sign_in", web::post().to(handlers::auth::sign_in))
            .route(
                "/verify_otp_for_signin",
                web::post().to(handlers::auth::verify_otp_for_signin),
            )
            .route(
                "/refresh_tokens",
                web::post().to(handlers::auth::refresh_tokens),
            )
            .route("/logout", web::get().to(handlers::auth::logout)),
    );
}
