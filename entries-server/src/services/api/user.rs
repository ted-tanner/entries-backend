use actix_web::web::*;

use crate::handlers::user;

pub fn configure(cfg: &mut ServiceConfig) {
    cfg.service(
        scope("/user")
            .route("", post().to(user::create))
            .route("", delete().to(user::init_delete))
            .route("/public_key", get().to(user::lookup_user_public_key))
            .route("/verify", get().to(user::verify_creation))
            .route("/preferences", put().to(user::edit_preferences))
            .route("/keystore", put().to(user::edit_keystore))
            .route("/password", put().to(user::change_password))
            .route("/recovery_key", put().to(user::change_recovery_key))
            .route("/deletion", get().to(user::is_listed_for_deletion))
            .route("/deletion", delete().to(user::cancel_delete))
            .route("/deletion/verify", get().to(user::delete)),
    );
}
