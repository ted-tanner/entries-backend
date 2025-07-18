use actix_web::{web, HttpRequest, HttpResponse, Responder};
use entries_common::db::DbThreadPool;
use serde_json::json;

use crate::env;

pub async fn heartbeat() -> impl Responder {
    HttpResponse::Ok()
}

pub async fn health(db_thread_pool: web::Data<DbThreadPool>, req: HttpRequest) -> impl Responder {
    let Some(key) = req.headers().get("Key") else {
        return HttpResponse::Unauthorized().finish();
    };

    let correct_key = &env::CONF.health_endpoint_key;

    if !keys_equal(key.as_bytes(), correct_key.as_bytes()) {
        return HttpResponse::Unauthorized().finish();
    }

    let thread_pool_state = db_thread_pool.state();
    let resp_body = json!({
        "db_thread_pool_state": {
            "connections": thread_pool_state.connections,
            "idle_connections": thread_pool_state.idle_connections,
            "max_connections": db_thread_pool.max_size()
        }
    });

    HttpResponse::Ok().json(resp_body)
}

fn keys_equal(key1: &[u8], key2: &[u8]) -> bool {
    if key1.len() != key2.len() {
        return false;
    }

    let mut keys_not_equal = 0;
    for i in 0..key1.len() {
        // This is safe because the lengths have already been checked and are equal
        keys_not_equal |= unsafe { key1.get_unchecked(i) ^ key2.get_unchecked(i) };
    }

    keys_not_equal == 0
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
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .route("/health", web::get().to(health)),
        )
        .await;

        let req = TestRequest::get()
            .uri("/health")
            .insert_header(("Key", env::CONF.health_endpoint_key.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);

        let resp_body = test::read_body(resp).await;
        let resp_json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();

        assert!(resp_json.get("db_thread_pool_state").is_some());
        let db_state = resp_json.get("db_thread_pool_state").unwrap();
        assert!(db_state.get("connections").is_some());
        assert!(db_state.get("idle_connections").is_some());
        assert!(db_state.get("max_connections").is_some());
    }

    #[actix_web::test]
    async fn test_health_with_invalid_key() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .route("/health", web::get().to(health)),
        )
        .await;

        let req = TestRequest::get()
            .uri("/health")
            .insert_header(("Key", "invalid_key"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_health_with_missing_key() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
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
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .route("/health", web::get().to(health)),
        )
        .await;

        let req = TestRequest::get()
            .uri("/health")
            .insert_header(("Key", "short"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_keys_equal() {
        let key1 = b"test_key_123";
        let key2 = b"test_key_123";
        let key3 = b"test_key_456";
        let key4 = b"test_key_12"; // shorter

        assert!(keys_equal(key1, key2));
        assert!(!keys_equal(key1, key3));
        assert!(!keys_equal(key1, key4));
        assert!(!keys_equal(key4, key1));
    }
}
