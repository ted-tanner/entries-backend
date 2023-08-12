use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/budget")
            .route("", web::get().to(handlers::budget::get))
            .route("", web::put().to(handlers::budget::edit))
            .route("", web::post().to(handlers::budget::create))
            .route("/multiple", web::get().to(handlers::budget::get_multiple))
            .route("/invitation", web::post().to(handlers::budget::invite_user))
            .route(
                "/invitation",
                web::delete().to(handlers::budget::retract_invitation),
            )
            .route(
                "/invitation/accept",
                web::put().to(handlers::budget::accept_invitation),
            )
            .route(
                "/invitation/decline",
                web::put().to(handlers::budget::decline_invitation),
            )
            .route(
                "/invitation/all_pending",
                web::get().to(handlers::budget::get_all_pending_invitations),
            )
            .route("/leave", web::delete().to(handlers::budget::leave_budget))
            .route("/entry", web::post().to(handlers::budget::create_entry))
            .route("/entry", web::put().to(handlers::budget::edit_entry))
            .route("/entry", web::delete().to(handlers::budget::delete_entry))
            .route(
                "/entry_and_category",
                web::post().to(handlers::budget::create_entry_and_category),
            )
            .route(
                "/category",
                web::post().to(handlers::budget::create_category),
            )
            .route("/category", web::put().to(handlers::budget::edit_category))
            .route(
                "/category",
                web::delete().to(handlers::budget::delete_category),
            ),
    );
}
