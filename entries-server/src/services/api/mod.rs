use std::time::Duration;

use actix_web::web::*;

use crate::middleware::Limiter;

mod auth;
mod container;
mod health;
mod user;

#[derive(Clone)]
pub struct RouteLimiters {
    pub create_container: Limiter,
    pub get_containers: Limiter,
    pub container_invite: Limiter,
    pub key_lookup: Limiter,
    pub create_user: Limiter,
    pub create_object: Limiter,
    pub password: Limiter,
    pub recovery: Limiter,
    pub verify_otp: Limiter,
    pub email: Limiter,
    pub refresh_tokens: Limiter,
    pub change_email: Limiter,
}

impl Default for RouteLimiters {
    fn default() -> Self {
        const CLEAR_FREQUENCY: Duration = Duration::from_secs(3600 * 24);

        Self {
            create_container: Limiter::new(10, Duration::from_secs(120), CLEAR_FREQUENCY),
            get_containers: Limiter::new(20, Duration::from_secs(10), CLEAR_FREQUENCY),
            container_invite: Limiter::new(10, Duration::from_secs(120), CLEAR_FREQUENCY),
            key_lookup: Limiter::new(30, Duration::from_secs(180), CLEAR_FREQUENCY),
            create_user: Limiter::new(5, Duration::from_secs(1200), CLEAR_FREQUENCY),
            create_object: Limiter::new(10, Duration::from_secs(10), CLEAR_FREQUENCY),
            password: Limiter::new(6, Duration::from_secs(600), CLEAR_FREQUENCY),
            recovery: Limiter::new(2, Duration::from_secs(600), CLEAR_FREQUENCY),
            verify_otp: Limiter::new(6, Duration::from_secs(60), CLEAR_FREQUENCY),
            email: Limiter::new(6, Duration::from_secs(360), CLEAR_FREQUENCY),
            refresh_tokens: Limiter::new(20, Duration::from_secs(180), CLEAR_FREQUENCY),
            change_email: Limiter::new(5, Duration::from_secs(1200), CLEAR_FREQUENCY),
        }
    }
}

pub fn configure(cfg: &mut ServiceConfig, limiters: RouteLimiters) {
    cfg.service(
        scope("/api")
            .configure(|cfg| auth::configure(cfg, limiters.clone()))
            .configure(|cfg| container::configure(cfg, limiters.clone()))
            .configure(|cfg| user::configure(cfg, limiters))
            .configure(health::configure),
    );
}
