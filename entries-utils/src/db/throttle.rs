use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
use std::time::SystemTime;

use crate::db::{DaoError, DbThreadPool};
use crate::models::throttleable_attempt::NewThrottleableAttempt;
use crate::schema::throttleable_attempts as throttleable_attempt_fields;
use crate::schema::throttleable_attempts::dsl::throttleable_attempts;

pub struct Dao {
    db_thread_pool: DbThreadPool,
}

impl Dao {
    pub fn new(db_thread_pool: &DbThreadPool) -> Self {
        Self {
            db_thread_pool: db_thread_pool.clone(),
        }
    }

    pub fn mark_attempt_and_get_attempt_count(
        &mut self,
        identifier_hash: i64,
        expiration: SystemTime,
    ) -> Result<i32, DaoError> {
        let new_attempt = NewThrottleableAttempt {
            identifier_hash,
            attempt_count: 1,
            expiration_timestamp: expiration,
        };

        let mut db_connection = self.db_thread_pool.get()?;

        let attempt_count = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let (attempt_count, curr_expiration) = dsl::insert_into(throttleable_attempts)
                    .values(&new_attempt)
                    .on_conflict(throttleable_attempt_fields::identifier_hash)
                    .do_update()
                    .set(
                        throttleable_attempt_fields::attempt_count
                            .eq(throttleable_attempt_fields::attempt_count + 1),
                    )
                    .returning((
                        throttleable_attempt_fields::attempt_count,
                        throttleable_attempt_fields::expiration_timestamp,
                    ))
                    .get_result::<(i32, SystemTime)>(conn)?;

                if curr_expiration < SystemTime::now() {
                    dsl::update(throttleable_attempts.find(identifier_hash))
                        .set((
                            throttleable_attempt_fields::attempt_count.eq(1),
                            throttleable_attempt_fields::expiration_timestamp.eq(expiration),
                        ))
                        .execute(conn)?;

                    return Ok(1);
                }

                Ok(attempt_count)
            })?;

        Ok(attempt_count)
    }

    pub fn clear_throttle_table(&mut self) -> Result<(), DaoError> {
        diesel::delete(throttleable_attempts).execute(&mut self.db_thread_pool.get()?)?;
        Ok(())
    }
}
