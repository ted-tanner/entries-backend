use actix_web::web;

mod auth;
mod user;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .configure(auth::configure)
            .configure(user::configure),
    );
}
