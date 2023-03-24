use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
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
            .route("/init_delete", web::put().to(handlers::user::init_delete))
            .route("/delete", web::get().to(handlers::user::delete))
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
