use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .route("", web::post().to(handlers::user::create))
            .route("", web::delete().to(handlers::user::init_delete))
            .route(
                "/public_key",
                web::get().to(handlers::user::lookup_user_public_key),
            )
            .route("/verify", web::get().to(handlers::user::verify_creation))
            .route(
                "/preferences",
                web::put().to(handlers::user::edit_preferences),
            )
            .route("/keystore", web::put().to(handlers::user::edit_keystore))
            .route("/password", web::put().to(handlers::user::change_password))
            .route(
                "/recovery_key",
                web::put().to(handlers::user::change_recovery_key),
            )
            .route(
                "/deletion",
                web::get().to(handlers::user::is_listed_for_deletion),
            )
            .route("/deletion", web::delete().to(handlers::user::cancel_delete))
            .route("/deletion/verify", web::get().to(handlers::user::delete)),
    );
}
