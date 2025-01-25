use actix_web::web::*;

use crate::handlers::budget;

use super::RouteLimiters;

pub fn configure(cfg: &mut ServiceConfig, limiters: RouteLimiters) {
    cfg.service(
        scope("/budget")
            .service(
                resource("")
                    .route(get().to(budget::get))
                    .wrap(limiters.get_budgets)
                    .route(put().to(budget::edit))
                    .route(post().to(budget::create).wrap(limiters.create_budget)),
            )
            .service(
                resource("invitation")
                    .route(post().to(budget::invite_user).wrap(limiters.budget_invite))
                    .route(delete().to(budget::retract_invitation)),
            )
            .service(resource("/invitation/accept").route(put().to(budget::accept_invitation)))
            .service(resource("/invitation/decline").route(put().to(budget::decline_invitation)))
            .service(
                resource("/invitation/all_pending")
                    .route(get().to(budget::get_all_pending_invitations)),
            )
            .service(resource("/leave").route(delete().to(budget::leave_budget)))
            .service(
                resource("/entry")
                    .route(post().to(budget::create_entry))
                    .route(put().to(budget::edit_entry))
                    .route(delete().to(budget::delete_entry)),
            )
            .service(
                resource("/entry_and_category").route(post().to(budget::create_entry_and_category)),
            )
            .service(
                resource("/category")
                    .route(post().to(budget::create_category))
                    .route(put().to(budget::edit_category))
                    .route(delete().to(budget::delete_category)),
            ),
    );
}
