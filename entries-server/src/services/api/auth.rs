use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route(
                "/nonce_and_auth_string_salt",
                web::get().to(handlers::auth::obtain_nonce_and_auth_string_params),
            )
            .route("/sign_in", web::post().to(handlers::auth::sign_in))
            .route(
                "/otp/verify",
                web::post().to(handlers::auth::verify_otp_for_signin),
            )
            .route(
                "/backup_code/use",
                web::post().to(handlers::auth::use_backup_code_for_signin),
            )
            .route(
                "/backup_code/regenerate",
                web::put().to(handlers::auth::regenerate_backup_codes),
            )
            .route("otp", web::get().to(handlers::auth::obtain_otp))
            .route(
                "/token/refresh",
                web::post().to(handlers::auth::refresh_tokens),
            )
            .route("/logout", web::post().to(handlers::auth::logout)),
    );
}
