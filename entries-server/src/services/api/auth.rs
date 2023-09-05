use actix_web::web::*;

use crate::handlers::auth;

pub fn configure(cfg: &mut ServiceConfig) {
    cfg.service(
        scope("/auth")
            .route(
                "/nonce_and_auth_string_params",
                get().to(auth::obtain_nonce_and_auth_string_params),
            )
            .route("/sign_in", post().to(auth::sign_in))
            .route("/otp/verify", post().to(auth::verify_otp_for_signin))
            .route(
                "/backup_code/use",
                post().to(auth::use_backup_code_for_signin),
            )
            .route(
                "/backup_code/regenerate",
                put().to(auth::regenerate_backup_codes),
            )
            .route("otp", get().to(auth::obtain_otp))
            .route("/token/refresh", post().to(auth::refresh_tokens))
            .route("/logout", post().to(auth::logout)),
    );
}
