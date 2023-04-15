use actix_web::web;

mod auth;
mod budget;
mod user;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .configure(auth::configure)
            .configure(budget::configure)
            .configure(user::configure),
    );
}
