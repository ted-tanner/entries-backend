use actix_web::web::*;

use crate::handlers::budget;

pub fn configure(cfg: &mut ServiceConfig) {
    cfg.service(
        scope("/budget")
            .route("", get().to(budget::get))
            .route("", put().to(budget::edit))
            .route("", post().to(budget::create))
            .route("/multiple", get().to(budget::get_multiple))
            .route("/invitation", post().to(budget::invite_user))
            .route("/invitation", delete().to(budget::retract_invitation))
            .route("/invitation/accept", put().to(budget::accept_invitation))
            .route("/invitation/decline", put().to(budget::decline_invitation))
            .route(
                "/invitation/all_pending",
                get().to(budget::get_all_pending_invitations),
            )
            .route("/leave", delete().to(budget::leave_budget))
            .route("/entry", post().to(budget::create_entry))
            .route("/entry", put().to(budget::edit_entry))
            .route("/entry", delete().to(budget::delete_entry))
            .route(
                "/entry_and_category",
                post().to(budget::create_entry_and_category),
            )
            .route("/category", post().to(budget::create_category))
            .route("/category", put().to(budget::edit_category))
            .route("/category", delete().to(budget::delete_category)),
    );
}
