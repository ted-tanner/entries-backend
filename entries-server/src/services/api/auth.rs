use actix_web::web::*;

use crate::handlers::auth;

use super::RateLimiters;

pub fn configure(cfg: &mut ServiceConfig, limiters: RateLimiters) {
    cfg.service(
        scope("/auth")
            .service(
                resource("/nonce-and-auth-string-params").route(
                    get()
                        .to(auth::obtain_nonce_and_auth_string_params)
                        .wrap(limiters.read_fair_use.clone())
                        .wrap(limiters.read_circuit_breaker.clone()),
                ),
            )
            .service(
                resource("/sign-in")
                    .route(post().to(auth::sign_in))
                    .wrap(limiters.expensive_auth_fair_use.clone())
                    .wrap(limiters.expensive_auth_circuit_breaker.clone()),
            )
            .service(
                resource("/recover-with-recovery-key")
                    .route(post().to(auth::recover_with_recovery_key))
                    .wrap(limiters.expensive_auth_fair_use.clone())
                    .wrap(limiters.expensive_auth_circuit_breaker.clone()),
            )
            .service(
                resource("/otp/verify").route(
                    post()
                        .to(auth::verify_otp_for_signin)
                        .wrap(limiters.light_auth_fair_use.clone())
                        .wrap(limiters.light_auth_circuit_breaker.clone()),
                ),
            )
            .service(
                resource("/otp").route(
                    get()
                        .to(auth::obtain_otp)
                        .wrap(limiters.light_auth_fair_use.clone())
                        .wrap(limiters.light_auth_circuit_breaker.clone()),
                ),
            )
            .service(
                resource("/otp/resend-signin-otp").route(
                    post()
                        .to(auth::resend_signin_otp)
                        .wrap(limiters.light_auth_fair_use.clone())
                        .wrap(limiters.light_auth_circuit_breaker.clone()),
                ),
            )
            .service(
                resource("/token/refresh").route(
                    post()
                        .to(auth::refresh_tokens)
                        .wrap(limiters.light_auth_fair_use.clone())
                        .wrap(limiters.light_auth_circuit_breaker.clone()),
                ),
            )
            .service(
                resource("/logout").route(
                    post()
                        .to(auth::logout)
                        .wrap(limiters.light_auth_fair_use)
                        .wrap(limiters.light_auth_circuit_breaker),
                ),
            ),
    );
}
