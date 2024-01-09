use actix_web::web::*;

use crate::handlers::auth;

use super::RouteLimiters;

pub fn configure(cfg: &mut ServiceConfig, limiters: RouteLimiters) {
    cfg.service(
        scope("/auth")
            .service(
                resource("/nonce_and_auth_string_params").route(
                    get()
                        .to(auth::obtain_nonce_and_auth_string_params)
                        .wrap(limiters.key_lookup),
                ),
            )
            .service(
                resource("/sign_in")
                    .route(post().to(auth::sign_in))
                    .wrap(limiters.password.clone()),
            )
            .service(
                resource("/backup_code/use").route(
                    post()
                        .to(auth::use_backup_code_for_signin)
                        .wrap(limiters.password),
                ),
            )
            .service(
                resource("/otp/verify").route(
                    post()
                        .to(auth::verify_otp_for_signin)
                        .wrap(limiters.verify_otp),
                ),
            )
            .service(
                resource("/backup_code/regenerate").route(
                    put()
                        .to(auth::regenerate_backup_codes)
                        .wrap(limiters.create_user),
                ),
            )
            .service(resource("/otp").route(get().to(auth::obtain_otp).wrap(limiters.email)))
            .service(
                resource("/token/refresh").route(
                    post()
                        .to(auth::refresh_tokens)
                        .wrap(limiters.refresh_tokens),
                ),
            )
            .service(resource("/logout").route(post().to(auth::logout))),
    );
}
