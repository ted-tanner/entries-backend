use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .route("/get", web::get().to(handlers::user::get))
            .route("/create", web::post().to(handlers::user::create))
            .route("/edit", web::put().to(handlers::user::edit))
            .route(
                "/change_password",
                web::put().to(handlers::user::change_password),
            )
            .route(
                "/send_buddy_request",
                web::post().to(handlers::user::send_buddy_request),
            )
            .route(
                "/retract_buddy_request",
                web::delete().to(handlers::user::retract_buddy_request),
            )
            .route(
                "/accept_buddy_request",
                web::put().to(handlers::user::accept_buddy_request),
            )
            .route(
                "/decline_buddy_request",
                web::put().to(handlers::user::decline_buddy_request),
            )
            .route(
                "/get_all_pending_buddy_requests_for_user",
                web::get().to(handlers::user::get_all_pending_buddy_requests_for_user),
            )
            .route(
                "/get_all_pending_buddy_requests_made_by_user",
                web::get().to(handlers::user::get_all_pending_buddy_requests_made_by_user),
            )
            .route(
                "/get_buddy_request",
                web::get().to(handlers::user::get_buddy_request),
            )
            .route(
                "/delete_buddy_relationship",
                web::delete().to(handlers::user::delete_buddy_relationship),
            )
            .route("/get_buddies", web::get().to(handlers::user::get_buddies)),
    );
}
