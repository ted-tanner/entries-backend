use budgetapp_utils::db::{self, DbThreadPool};

use actix_web::dev::Payload;
use actix_web::{web, FromRequest, HttpRequest};
use futures::future;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::num::Wrapping;
use std::time::{Duration, SystemTime};

use crate::handlers::error::HttpErrorResponse;

pub struct Throttle<const TRIES: i32, const MINS: u64> {}

impl<const TRIES: i32, const MINS: u64> Throttle<TRIES, MINS> {
    pub async fn enforce<T: Hash>(
        &self,
        identifier: &T,
        handler_name: &'static str,
        db_thread_pool: &DbThreadPool,
    ) -> Result<(), HttpErrorResponse> {
        let mut hasher = DefaultHasher::new();
        identifier.hash(&mut hasher);
        let identifier_hash = Wrapping(hasher.finish());

        let mut hasher = DefaultHasher::new();
        handler_name.hash(&mut hasher);
        let name_hash = Wrapping(hasher.finish());

        let combined_hash = (identifier_hash << 1) + identifier_hash + name_hash;

        // Reinterpret the u64 hash as an i64 (Postgres supports i64s but not u64s).
        // This is safe and does not affect the uniqueness of the hash value.
        let combined_hash = unsafe { std::mem::transmute::<_, i64>(combined_hash.0) };
        let mut dao = db::throttle::Dao::new(&db_thread_pool);

        let attempt_count = match web::block(move || {
            let expiration_time = SystemTime::now() + Duration::from_secs(60 * MINS);
            dao.mark_attempt_and_get_attempt_count(combined_hash, expiration_time)
        })
        .await?
        {
            Ok(a) => a,
            Err(e) => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(
                    "Failed to check attempt count",
                ));
            }
        };

        if attempt_count > TRIES {
            return Err(HttpErrorResponse::TooManyAttempts(
                "Too many recent attempts",
            ));
        }

        Ok(())
    }
}

impl<const TRIES: i32, const MINS: u64> FromRequest for Throttle<TRIES, MINS> {
    type Error = actix_web::error::Error;
    type Future = future::Ready<Result<Self, Self::Error>>;

    fn from_request(_req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        future::ok(Self {})
    }
}
