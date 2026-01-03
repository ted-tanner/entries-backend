use actix_web::web::*;

use crate::env::CONF;
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
        Self {
            create_container: Limiter::new(
                CONF.api_create_container_limiter_max_per_period,
                CONF.api_create_container_limiter_period,
                CONF.api_limiter_clear_frequency,
                "create_container",
            ),
            get_containers: Limiter::new(
                CONF.api_get_containers_limiter_max_per_period,
                CONF.api_get_containers_limiter_period,
                CONF.api_limiter_clear_frequency,
                "get_containers",
            ),
            container_invite: Limiter::new(
                CONF.api_container_invite_limiter_max_per_period,
                CONF.api_container_invite_limiter_period,
                CONF.api_limiter_clear_frequency,
                "container_invite",
            ),
            key_lookup: Limiter::new(
                CONF.api_key_lookup_limiter_max_per_period,
                CONF.api_key_lookup_limiter_period,
                CONF.api_limiter_clear_frequency,
                "key_lookup",
            ),
            create_user: Limiter::new(
                CONF.api_create_user_limiter_max_per_period,
                CONF.api_create_user_limiter_period,
                CONF.api_limiter_clear_frequency,
                "create_user",
            ),
            create_object: Limiter::new(
                CONF.api_create_object_limiter_max_per_period,
                CONF.api_create_object_limiter_period,
                CONF.api_limiter_clear_frequency,
                "create_object",
            ),
            password: Limiter::new(
                CONF.api_password_limiter_max_per_period,
                CONF.api_password_limiter_period,
                CONF.api_limiter_clear_frequency,
                "password",
            ),
            recovery: Limiter::new(
                CONF.api_recovery_limiter_max_per_period,
                CONF.api_recovery_limiter_period,
                CONF.api_limiter_clear_frequency,
                "recovery",
            ),
            verify_otp: Limiter::new(
                CONF.api_verify_otp_limiter_max_per_period,
                CONF.api_verify_otp_limiter_period,
                CONF.api_limiter_clear_frequency,
                "verify_otp",
            ),
            email: Limiter::new(
                CONF.api_email_limiter_max_per_period,
                CONF.api_email_limiter_period,
                CONF.api_limiter_clear_frequency,
                "email",
            ),
            refresh_tokens: Limiter::new(
                CONF.api_refresh_tokens_limiter_max_per_period,
                CONF.api_refresh_tokens_limiter_period,
                CONF.api_limiter_clear_frequency,
                "refresh_tokens",
            ),
            change_email: Limiter::new(
                CONF.api_change_email_limiter_max_per_period,
                CONF.api_change_email_limiter_period,
                CONF.api_limiter_clear_frequency,
                "change_email",
            ),
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
