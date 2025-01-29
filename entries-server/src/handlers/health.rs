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
