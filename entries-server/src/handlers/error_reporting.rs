use std::{
    cell::UnsafeCell,
    ptr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        OnceLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::env;

const CLIENT_ERR_LOG_LEN: usize = 5_000;
const CLIENT_ERR_MSG_MAX_LEN: usize = 128;
const CLIENT_ERR_LOG_LOCK_SHARD_COUNT: usize = 256;

static CLIENT_ERROR_LOG_INDEX: AtomicUsize = AtomicUsize::new(0);
static CLIENT_ERROR_LOG_LOCKS: OnceLock<[Mutex<()>; CLIENT_ERR_LOG_LOCK_SHARD_COUNT]> =
    OnceLock::new();

#[inline(always)]
fn get_client_error_log() -> &'static [Mutex<()>; CLIENT_ERR_LOG_LOCK_SHARD_COUNT] {
    CLIENT_ERROR_LOG_LOCKS.get_or_init(|| std::array::from_fn(|_| Mutex::new(())))
}

#[repr(transparent)]
struct ClientErrorLogEntryCell(UnsafeCell<ClientErrorLogEntry>);

// SAFETY: All mutation of the inner entry is synchronized via the per-shard async mutex.
//         We never hand out `&mut` references to the inner entry; mutation is done via raw pointers.
unsafe impl Sync for ClientErrorLogEntryCell {}

static CLIENT_ERROR_LOG: [ClientErrorLogEntryCell; CLIENT_ERR_LOG_LEN] = [const {
    ClientErrorLogEntryCell(UnsafeCell::new(ClientErrorLogEntry {
        msg: [0; CLIENT_ERR_MSG_MAX_LEN],
        len: 0,
        timestamp_ms: 0,
    }))
}; CLIENT_ERR_LOG_LEN];

struct ClientErrorLogEntry {
    msg: [u8; CLIENT_ERR_MSG_MAX_LEN],
    len: usize,
    timestamp_ms: u64,
}

#[derive(Serialize)]
pub struct ClientErrorLogEntrySnapshot {
    msg: String,
    timestamp_ms: u64,
}

#[derive(Deserialize)]
pub struct ClientErrorLogKeyQuery {
    pub key: Option<String>,
}

#[inline]
fn is_endpoint_key_correct(key: Option<&str>) -> bool {
    let Some(key) = key else {
        return false;
    };

    let correct_key = env::CONF.client_errors_endpoint_key.as_bytes();
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

pub async fn report_error(body: String) -> HttpResponse {
    let idx = CLIENT_ERROR_LOG_INDEX.fetch_add(1, Ordering::Relaxed) % CLIENT_ERR_LOG_LEN;
    let message = body.as_str();

    let shard = idx % CLIENT_ERR_LOG_LOCK_SHARD_COUNT;
    let _guard = get_client_error_log()[shard].lock().await;

    unsafe {
        let entry_ptr = CLIENT_ERROR_LOG[idx].0.get();

        let msg_bytes = message.as_bytes();
        let msg_len = std::cmp::min(msg_bytes.len(), CLIENT_ERR_MSG_MAX_LEN);
        ptr::copy_nonoverlapping(msg_bytes.as_ptr(), (*entry_ptr).msg.as_mut_ptr(), msg_len);
        (*entry_ptr).len = msg_len;

        let now = SystemTime::now();
        (*entry_ptr).timestamp_ms = now
            .duration_since(UNIX_EPOCH)
            .expect("System time should be after Unix Epoch")
            .as_millis()
            .try_into()
            .expect("Milliseconds since Unix Epoch should fit in a u64");
    }

    HttpResponse::Ok().finish()
}

pub async fn get_client_errors(query: web::Query<ClientErrorLogKeyQuery>) -> HttpResponse {
    if !is_endpoint_key_correct(query.key.as_deref()) {
        return HttpResponse::Unauthorized().finish();
    }

    let mut out = Vec::new();

    // Lock each shard once, snapshot all entries in that shard, then unlock
    for shard in 0..CLIENT_ERR_LOG_LOCK_SHARD_COUNT {
        let _guard = get_client_error_log()[shard].lock().await;

        let mut idx = shard;
        while idx < CLIENT_ERR_LOG_LEN {
            unsafe {
                let entry_ptr = CLIENT_ERROR_LOG[idx].0.get();

                let timestamp_ms = (*entry_ptr).timestamp_ms;
                if timestamp_ms == 0 {
                    idx += CLIENT_ERR_LOG_LOCK_SHARD_COUNT;
                    continue;
                }

                let len = std::cmp::min((*entry_ptr).len, CLIENT_ERR_MSG_MAX_LEN);
                if len == 0 {
                    idx += CLIENT_ERR_LOG_LOCK_SHARD_COUNT;
                    continue;
                }

                let mut buf = vec![0u8; len];
                ptr::copy_nonoverlapping((*entry_ptr).msg.as_ptr(), buf.as_mut_ptr(), len);
                let msg = String::from_utf8_lossy(&buf).to_string();

                out.push(ClientErrorLogEntrySnapshot { msg, timestamp_ms });
            }

            idx += CLIENT_ERR_LOG_LOCK_SHARD_COUNT;
        }
    }

    // Sort after snapshotting so we don't hold locks longer than needed.
    out.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));

    HttpResponse::Ok().json(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::body::to_bytes;
    use actix_web::http::{header, StatusCode};
    use actix_web::test::{self, TestRequest};
    use actix_web::web::{get, post, resource, scope};
    use actix_web::App;
    use serde::Deserialize;
    use tokio::sync::Mutex as TokioMutex;

    static TEST_LOCK: OnceLock<TokioMutex<()>> = OnceLock::new();

    fn test_lock() -> &'static TokioMutex<()> {
        TEST_LOCK.get_or_init(|| TokioMutex::new(()))
    }

    async fn reset_client_error_log() {
        // Clear the in-memory buffer so tests are deterministic.
        for shard in 0..CLIENT_ERR_LOG_LOCK_SHARD_COUNT {
            let _guard = get_client_error_log()[shard].lock().await;

            let mut idx = shard;
            while idx < CLIENT_ERR_LOG_LEN {
                unsafe {
                    let entry_ptr = CLIENT_ERROR_LOG[idx].0.get();
                    (*entry_ptr).len = 0;
                    (*entry_ptr).timestamp_ms = 0;
                }
                idx += CLIENT_ERR_LOG_LOCK_SHARD_COUNT;
            }
        }

        CLIENT_ERROR_LOG_INDEX.store(0, Ordering::Relaxed);
    }

    #[derive(Deserialize)]
    struct Snapshot {
        msg: String,
        timestamp_ms: u64,
    }

    #[actix_web::test]
    async fn test_get_client_errors_requires_key() {
        let _guard = test_lock().lock().await;
        reset_client_error_log().await;

        let app = test::init_service(
            App::new().service(
                scope("/api").service(
                    resource("/client-errors")
                        .route(get().to(get_client_errors))
                        .route(post().to(report_error)),
                ),
            ),
        )
        .await;

        let req = TestRequest::get().uri("/api/client-errors").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_get_client_errors_wrong_key_unauthorized() {
        let _guard = test_lock().lock().await;
        reset_client_error_log().await;

        let app = test::init_service(
            App::new().service(
                scope("/api").service(
                    resource("/client-errors")
                        .route(get().to(get_client_errors))
                        .route(post().to(report_error)),
                ),
            ),
        )
        .await;

        let req = TestRequest::get()
            .uri("/api/client-errors?key=wrong")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_get_client_errors_empty_when_no_entries() {
        let _guard = test_lock().lock().await;
        reset_client_error_log().await;

        let app = test::init_service(
            App::new().service(
                scope("/api").service(
                    resource("/client-errors")
                        .route(get().to(get_client_errors))
                        .route(post().to(report_error)),
                ),
            ),
        )
        .await;
        let key = &env::CONF.client_errors_endpoint_key;

        let req = TestRequest::get()
            .uri(&format!("/api/client-errors?key={key}"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = to_bytes(resp.into_body()).await.unwrap();
        let snaps: Vec<Snapshot> = serde_json::from_slice(&bytes).unwrap();
        assert!(snaps.is_empty());
    }

    #[actix_web::test]
    async fn test_post_no_auth_and_get_returns_sorted_entries() {
        let _guard = test_lock().lock().await;
        reset_client_error_log().await;

        let app = test::init_service(
            App::new().service(
                scope("/api").service(
                    resource("/client-errors")
                        .route(get().to(get_client_errors))
                        .route(post().to(report_error)),
                ),
            ),
        )
        .await;

        // POST does not require a key
        let req = TestRequest::post()
            .uri("/api/client-errors")
            .insert_header((header::CONTENT_TYPE, "text/plain; charset=utf-8"))
            .set_payload("first")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Ensure different timestamps for ordering expectations.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;

        let req = TestRequest::post()
            .uri("/api/client-errors")
            .insert_header((header::CONTENT_TYPE, "text/plain; charset=utf-8"))
            .set_payload("second")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let key = &env::CONF.client_errors_endpoint_key;
        let req = TestRequest::get()
            .uri(&format!("/api/client-errors?key={key}"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = to_bytes(resp.into_body()).await.unwrap();
        let snaps: Vec<Snapshot> = serde_json::from_slice(&bytes).unwrap();

        // Should include our two entries.
        let first_idx = snaps.iter().position(|s| s.msg == "first").unwrap();
        let second_idx = snaps.iter().position(|s| s.msg == "second").unwrap();

        // All returned entries should be initialized.
        assert!(snaps.iter().all(|s| s.timestamp_ms > 0));

        // Sorted descending by timestamp_ms.
        for w in snaps.windows(2) {
            assert!(w[0].timestamp_ms >= w[1].timestamp_ms);
        }

        // And because we slept, "second" should be newer.
        assert!(second_idx < first_idx);
    }
}
