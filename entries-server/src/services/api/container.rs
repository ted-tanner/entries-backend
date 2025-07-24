use actix_web::web::*;

use crate::handlers::container;

use super::RouteLimiters;

pub fn configure(cfg: &mut ServiceConfig, limiters: RouteLimiters) {
    cfg.service(
        scope("/container")
            .service(
                resource("")
                    .route(get().to(container::get))
                    .wrap(limiters.get_containers)
                    .route(put().to(container::edit))
                    .route(post().to(container::create).wrap(limiters.create_container)),
            )
            .service(
                scope("/invitation")
                    .service(
                        resource("")
                            .route(
                                post()
                                    .to(container::invite_user)
                                    .wrap(limiters.container_invite),
                            )
                            .route(delete().to(container::retract_invitation)),
                    )
                    .service(resource("/accept").route(put().to(container::accept_invitation)))
                    .service(resource("/decline").route(put().to(container::decline_invitation)))
                    .service(
                        resource("/all_pending")
                            .route(get().to(container::get_all_pending_invitations)),
                    ),
            )
            .service(resource("/leave").route(delete().to(container::leave_container)))
            .service(
                resource("/entry")
                    .route(post().to(container::create_entry))
                    .wrap(limiters.create_object.clone())
                    .route(put().to(container::edit_entry))
                    .route(delete().to(container::delete_entry)),
            )
            .service(
                resource("/entry_and_category")
                    .route(post().to(container::create_entry_and_category))
                    .wrap(limiters.create_object.clone()),
            )
            .service(
                resource("/category")
                    .route(post().to(container::create_category))
                    .wrap(limiters.create_object)
                    .route(put().to(container::edit_category))
                    .route(delete().to(container::delete_category)),
            ),
    );
}
