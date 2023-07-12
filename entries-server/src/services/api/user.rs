use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .route(
                "/lookup_user_public_key",
                web::get().to(handlers::user::lookup_user_public_key),
            )
            .route("/create", web::post().to(handlers::user::create))
            .route(
                "/verify_creation",
                web::get().to(handlers::user::verify_creation),
            )
            .route(
                "/edit_preferences",
                web::put().to(handlers::user::edit_preferences),
            )
            .route(
                "/edit_keystore",
                web::put().to(handlers::user::edit_keystore),
            )
            .route(
                "/change_password",
                web::put().to(handlers::user::change_password),
            )
            .route(
                "/change_recovery_key",
                web::put().to(handlers::user::change_recovery_key),
            )
            .route(
                "/init_delete",
                web::delete().to(handlers::user::init_delete),
            )
            .route("/verify_deletion", web::get().to(handlers::user::delete))
            .route(
                "/is_listed_for_deletion",
                web::get().to(handlers::user::is_listed_for_deletion),
            )
            .route(
                "/cancel_delete",
                web::put().to(handlers::user::cancel_delete),
            ),
    );
}
