use actix_web::{web, HttpResponse, Responder};
use entries_common::db::DbAsyncPool;
use serde::Deserialize;
use serde_json::json;

use crate::env;

#[derive(Deserialize)]
pub struct HealthKeyQuery {
    pub key: Option<String>,
}

pub async fn heartbeat() -> impl Responder {
    HttpResponse::Ok()
}

pub async fn health(
    db_async_pool: web::Data<DbAsyncPool>,
    query: web::Query<HealthKeyQuery>,
) -> impl Responder {
    if !is_health_key_correct(query.key.as_deref()) {
        return HttpResponse::Unauthorized().finish();
    }

    let async_pool_state = db_async_pool.state();
    let resp_body = json!({
        "db_async_pool_state": {
            "connections": async_pool_state.connections,
            "idle_connections": async_pool_state.idle_connections
        }
    });

    HttpResponse::Ok().json(resp_body)
}

#[inline]
fn is_health_key_correct(key: Option<&str>) -> bool {
    let Some(key) = key else {
        return false;
    };

    let correct_key = env::CONF.health_endpoint_key.as_bytes();
    let key = key.as_bytes();

    let mut keys_dont_match = 0u8;

    if correct_key.len() != key.len() || key.is_empty() {
        return false;
    }

    // Do bitwise comparison to prevent timing attacks
    for (i, correct_key_byte) in correct_key.iter().enumerate() {
        unsafe {
            keys_dont_match |= correct_key_byte ^ key.get_unchecked(i);
        }
    }

    keys_dont_match == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::{self, TestRequest};
    use actix_web::web::Data;
    use actix_web::App;

    #[actix_web::test]
    async fn test_heartbeat() {
        let app =
            test::init_service(App::new().route("/heartbeat", web::get().to(heartbeat))).await;

        let req = TestRequest::get().uri("/heartbeat").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_health_with_valid_key() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .route("/health", web::get().to(health)),
        )
        .await;

        let req = TestRequest::get()
            .uri(&format!("/health?key={}", env::CONF.health_endpoint_key))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);

        let resp_body = test::read_body(resp).await;
        let resp_json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();

        assert!(resp_json.get("db_async_pool_state").is_some());
        let db_state = resp_json.get("db_async_pool_state").unwrap();
        assert!(db_state.get("connections").is_some());
        assert!(db_state.get("idle_connections").is_some());
    }

    #[actix_web::test]
    async fn test_health_with_invalid_key() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .route("/health", web::get().to(health)),
        )
        .await;

        let req = TestRequest::get()
            .uri("/health?key=invalid_key")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_health_with_missing_key() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .route("/health", web::get().to(health)),
        )
        .await;

        let req = TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_health_with_wrong_length_key() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .route("/health", web::get().to(health)),
        )
        .await;

        let req = TestRequest::get().uri("/health?key=short").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }
}
