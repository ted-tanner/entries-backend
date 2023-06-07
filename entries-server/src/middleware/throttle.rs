use entries_utils::db::{self, DbThreadPool};

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
        let mut dao = db::throttle::Dao::new(db_thread_pool);

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

#[cfg(test)]
mod tests {
    use crate::env;

    use super::*;

    use actix_web::dev::Payload;
    use actix_web::test::TestRequest;
    use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
    use entries_utils::schema::throttleable_attempts;
    use uuid::Uuid;

    #[actix_web::test]
    async fn test_throttle_works() {
        const TEST_ID: &str = "test";
        const EXP_MINS: u64 = 1;

        let req = TestRequest::default().to_http_request();
        let throttle = Throttle::<3, EXP_MINS>::from_request(&req, &mut Payload::None)
            .await
            .unwrap();

        let db = &env::testing::DB_THREAD_POOL;
        let ident = Uuid::new_v4();

        assert!(throttle.enforce(&ident, TEST_ID, db).await.is_ok());
        assert!(throttle.enforce(&ident, TEST_ID, db).await.is_ok());
        assert!(throttle.enforce(&ident, TEST_ID, db).await.is_ok());
        assert!(throttle.enforce(&ident, TEST_ID, db).await.is_err());

        let mut hasher = DefaultHasher::new();
        ident.hash(&mut hasher);
        let identifier_hash = Wrapping(hasher.finish());

        let mut hasher = DefaultHasher::new();
        TEST_ID.hash(&mut hasher);
        let name_hash = Wrapping(hasher.finish());

        let combined_hash = (identifier_hash << 1) + identifier_hash + name_hash;
        let combined_hash = unsafe { std::mem::transmute::<_, i64>(combined_hash.0) };

        dsl::update(throttleable_attempts::table.find(combined_hash))
            .set(throttleable_attempts::expiration_timestamp.eq(SystemTime::now()))
            .execute(&mut db.get().unwrap())
            .unwrap();

        assert!(throttle.enforce(&ident, TEST_ID, db).await.is_ok());
        assert!(throttle.enforce(&ident, TEST_ID, db).await.is_ok());
        assert!(throttle.enforce(&ident, TEST_ID, db).await.is_ok());
        assert!(throttle.enforce(&ident, TEST_ID, db).await.is_err());
    }
}
