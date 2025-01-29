use std::time::Duration;

use actix_web::web::*;

use crate::middleware::Limiter;

mod auth;
mod budget;
mod health;
mod user;

#[derive(Clone)]
pub struct RouteLimiters {
    pub create_budget: Limiter,
    pub get_budgets: Limiter,
    pub budget_invite: Limiter,
    pub key_lookup: Limiter,
    pub create_user: Limiter,
    pub password: Limiter,
    pub verify_otp: Limiter,
    pub email: Limiter,
    pub refresh_tokens: Limiter,
}

impl Default for RouteLimiters {
    fn default() -> Self {
        const CLEAR_FREQUENCY: Duration = Duration::from_secs(3600 * 24);

        Self {
            create_budget: Limiter::new(10, Duration::from_secs(120), CLEAR_FREQUENCY),
            get_budgets: Limiter::new(15, Duration::from_secs(10), CLEAR_FREQUENCY),
            budget_invite: Limiter::new(10, Duration::from_secs(120), CLEAR_FREQUENCY),
            key_lookup: Limiter::new(30, Duration::from_secs(180), CLEAR_FREQUENCY),
            create_user: Limiter::new(5, Duration::from_secs(1200), CLEAR_FREQUENCY),
            password: Limiter::new(6, Duration::from_secs(600), CLEAR_FREQUENCY),
            verify_otp: Limiter::new(6, Duration::from_secs(60), CLEAR_FREQUENCY),
            email: Limiter::new(6, Duration::from_secs(360), CLEAR_FREQUENCY),
            refresh_tokens: Limiter::new(20, Duration::from_secs(180), CLEAR_FREQUENCY),
        }
    }
}

pub fn configure(cfg: &mut ServiceConfig, limiters: RouteLimiters) {
    cfg.service(
        scope("/api")
            .configure(|cfg| auth::configure(cfg, limiters.clone()))
            .configure(|cfg| budget::configure(cfg, limiters.clone()))
            .configure(health::configure)
            .configure(|cfg| user::configure(cfg, limiters)),
    );
}
