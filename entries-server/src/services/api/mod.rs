use actix_web::web::*;

use crate::env::CONF;
use crate::middleware::{CircuitBreakerStrategy, FairUseStrategy, RateLimiter};

mod auth;
mod container;
mod error_reporting;
mod health;
mod user;

#[derive(Clone)]
pub struct RateLimiters {
    pub create_fair_use: RateLimiter<FairUseStrategy, 32>,
    pub read_fair_use: RateLimiter<FairUseStrategy, 32>,
    pub modify_fair_use: RateLimiter<FairUseStrategy, 32>,
    pub expensive_auth_fair_use: RateLimiter<FairUseStrategy, 32>,
    pub light_auth_fair_use: RateLimiter<FairUseStrategy, 32>,

    pub create_circuit_breaker: RateLimiter<CircuitBreakerStrategy, 32>,
    pub read_circuit_breaker: RateLimiter<CircuitBreakerStrategy, 32>,
    pub modify_circuit_breaker: RateLimiter<CircuitBreakerStrategy, 32>,
    pub expensive_auth_circuit_breaker: RateLimiter<CircuitBreakerStrategy, 32>,
    pub light_auth_circuit_breaker: RateLimiter<CircuitBreakerStrategy, 32>,
}

impl Default for RateLimiters {
    fn default() -> Self {
        Self {
            create_fair_use: RateLimiter::<FairUseStrategy, 32>::new(
                CONF.api_create_fair_use_limiter_max_per_period,
                CONF.api_create_fair_use_limiter_period,
                CONF.api_limiter_clear_frequency,
                "create_fair_use",
            ),
            read_fair_use: RateLimiter::<FairUseStrategy, 32>::new(
                CONF.api_read_fair_use_limiter_max_per_period,
                CONF.api_read_fair_use_limiter_period,
                CONF.api_limiter_clear_frequency,
                "read_fair_use",
            ),
            modify_fair_use: RateLimiter::<FairUseStrategy, 32>::new(
                CONF.api_modify_fair_use_limiter_max_per_period,
                CONF.api_modify_fair_use_limiter_period,
                CONF.api_limiter_clear_frequency,
                "modify_fair_use",
            ),
            expensive_auth_fair_use: RateLimiter::<FairUseStrategy, 32>::new(
                CONF.api_expensive_auth_fair_use_limiter_max_per_period,
                CONF.api_expensive_auth_fair_use_limiter_period,
                CONF.api_limiter_clear_frequency,
                "expensive_auth_fair_use",
            ),
            light_auth_fair_use: RateLimiter::<FairUseStrategy, 32>::new(
                CONF.api_light_auth_fair_use_limiter_max_per_period,
                CONF.api_light_auth_fair_use_limiter_period,
                CONF.api_limiter_clear_frequency,
                "light_auth_fair_use",
            ),

            create_circuit_breaker: RateLimiter::<CircuitBreakerStrategy, 32>::new(
                CONF.api_create_circuit_breaker_limiter_max_per_period,
                CONF.api_create_circuit_breaker_limiter_period,
                CONF.api_limiter_clear_frequency,
                "create_circuit_breaker",
            ),
            read_circuit_breaker: RateLimiter::<CircuitBreakerStrategy, 32>::new(
                CONF.api_read_circuit_breaker_limiter_max_per_period,
                CONF.api_read_circuit_breaker_limiter_period,
                CONF.api_limiter_clear_frequency,
                "read_circuit_breaker",
            ),
            modify_circuit_breaker: RateLimiter::<CircuitBreakerStrategy, 32>::new(
                CONF.api_modify_circuit_breaker_limiter_max_per_period,
                CONF.api_modify_circuit_breaker_limiter_period,
                CONF.api_limiter_clear_frequency,
                "modify_circuit_breaker",
            ),
            expensive_auth_circuit_breaker: RateLimiter::<CircuitBreakerStrategy, 32>::new(
                CONF.api_expensive_auth_circuit_breaker_limiter_max_per_period,
                CONF.api_expensive_auth_circuit_breaker_limiter_period,
                CONF.api_limiter_clear_frequency,
                "expensive_auth_circuit_breaker",
            ),
            light_auth_circuit_breaker: RateLimiter::<CircuitBreakerStrategy, 32>::new(
                CONF.api_light_auth_circuit_breaker_limiter_max_per_period,
                CONF.api_light_auth_circuit_breaker_limiter_period,
                CONF.api_limiter_clear_frequency,
                "light_auth_circuit_breaker",
            ),
        }
    }
}

pub fn configure(cfg: &mut ServiceConfig, limiters: RateLimiters) {
    cfg.service(
        scope("/api")
            .configure(|cfg| auth::configure(cfg, limiters.clone()))
            .configure(|cfg| container::configure(cfg, limiters.clone()))
            .configure(|cfg| error_reporting::configure(cfg, limiters.clone()))
            .configure(|cfg| user::configure(cfg, limiters.clone()))
            .configure(|cfg| health::configure(cfg, limiters)),
    );
}
