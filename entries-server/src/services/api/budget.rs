use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/budget")
            .route("/get", web::get().to(handlers::budget::get))
            .route(
                "/get_multiple",
                web::put().to(handlers::budget::get_multiple),
            )
            .route("/create", web::post().to(handlers::budget::create))
            .route("/edit", web::put().to(handlers::budget::edit))
            .route(
                "/invite_user",
                web::post().to(handlers::budget::invite_user),
            )
            .route(
                "/retract_invitation",
                web::delete().to(handlers::budget::retract_invitation),
            )
            .route(
                "/accept_invitation",
                web::put().to(handlers::budget::accept_invitation),
            )
            .route(
                "/decline_invitation",
                web::put().to(handlers::budget::decline_invitation),
            )
            .route(
                "/get_all_pending_invitations",
                web::get().to(handlers::budget::get_all_pending_invitations),
            )
            .route(
                "/leave_budget",
                web::delete().to(handlers::budget::leave_budget),
            )
            .route(
                "/create_entry",
                web::post().to(handlers::budget::create_entry),
            )
            .route(
                "/create_entry_and_category",
                web::post().to(handlers::budget::create_entry_and_category),
            )
            .route("/edit_entry", web::put().to(handlers::budget::edit_entry))
            .route(
                "/delete_entry",
                web::delete().to(handlers::budget::delete_entry),
            )
            .route(
                "/create_category",
                web::post().to(handlers::budget::create_category),
            )
            .route(
                "/edit_category",
                web::put().to(handlers::budget::edit_category),
            )
            .route(
                "/delete_category",
                web::delete().to(handlers::budget::delete_category),
            ),
    );
}
