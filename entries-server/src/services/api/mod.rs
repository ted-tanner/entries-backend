use actix_web::web::*;

mod auth;
mod budget;
mod user;

pub fn configure(cfg: &mut ServiceConfig) {
    cfg.service(
        scope("/api")
            .configure(auth::configure)
            .configure(budget::configure)
            .configure(user::configure),
    );
}
