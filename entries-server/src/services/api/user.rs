use actix_web::web::*;

use crate::handlers::user;

use super::RouteLimiters;

pub fn configure(cfg: &mut ServiceConfig, limiters: RouteLimiters) {
    cfg.service(
        scope("/user")
            .service(
                resource("")
                    .route(post().to(user::create).wrap(limiters.create_user))
                    .route(delete().to(user::init_delete).wrap(limiters.email)),
            )
            .service(
                resource("/public_key")
                    .route(
                        get()
                            .to(user::lookup_user_public_key)
                            .wrap(limiters.key_lookup),
                    )
                    .route(put().to(user::rotate_user_public_key)),
            )
            .service(resource("/verify").route(get().to(user::verify_creation)))
            .service(resource("/preferences").route(put().to(user::edit_preferences)))
            .service(resource("/keystore").route(put().to(user::edit_keystore)))
            .service(
                resource("/password").route(
                    put()
                        .to(user::change_password)
                        .wrap(limiters.password.clone()),
                ),
            )
            .service(
                resource("/recovery_key")
                    .route(put().to(user::change_recovery_key).wrap(limiters.password)),
            )
            .service(
                resource("/email").route(put().to(user::change_email).wrap(limiters.change_email)),
            )
            .service(
                resource("/deletion")
                    .route(get().to(user::is_listed_for_deletion))
                    .route(delete().to(user::cancel_delete)),
            )
            .service(resource("/deletion/verify").route(get().to(user::delete))),
    );
}
