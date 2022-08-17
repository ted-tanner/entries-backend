use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/budget")
            .route("/get", web::get().to(handlers::budget::get))
            .route("/get_all", web::get().to(handlers::budget::get_all))
            .route(
                "/get_all_between_dates",
                web::get().to(handlers::budget::get_all_between_dates),
            )
            .route("/create", web::post().to(handlers::budget::create))
            .route("/edit", web::put().to(handlers::budget::edit))
            .route("/add_entry", web::post().to(handlers::budget::add_entry))
            .route("/invite", web::post().to(handlers::budget::invite_user))
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
                "/get_all_pending_invitations_for_user",
                web::get().to(handlers::budget::get_all_pending_invitations_for_user),
            )
            .route(
                "/get_all_pending_invitations_made_by_user",
                web::get().to(handlers::budget::get_all_pending_invitations_made_by_user),
            )
            .route(
                "/get_invitation",
                web::get().to(handlers::budget::get_invitation),
            )
            .route(
                "/remove_budget",
                web::delete().to(handlers::budget::remove_budget),
            ),
    );
}
