use entries_utils::db::throttle::Dao as ThrottleDao;
use entries_utils::db::DbThreadPool;

use async_trait::async_trait;

use crate::jobs::{Job, JobError};

pub struct ClearThrottleTableJob {
    db_thread_pool: DbThreadPool,
    is_running: bool,
}

impl ClearThrottleTableJob {
    pub fn new(db_thread_pool: DbThreadPool) -> Self {
        Self {
            db_thread_pool,
            is_running: false,
        }
    }
}

#[async_trait]
impl Job for ClearThrottleTableJob {
    fn name(&self) -> &'static str {
        "Clear Throttle Table"
    }

    fn is_ready(&self) -> bool {
        !self.is_running
    }

    async fn execute(&mut self) -> Result<(), JobError> {
        self.is_running = true;

        let dao = ThrottleDao::new(&self.db_thread_pool);
        tokio::task::spawn_blocking(move || dao.clear_throttle_table()).await??;

        self.is_running = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use diesel::{QueryDsl, RunQueryDsl};
    use entries_utils::db::throttle;
    use entries_utils::schema::throttleable_attempts;
    use rand::Rng;

    use crate::env;

    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_execute() {
        let dao = throttle::Dao::new(&env::testing::DB_THREAD_POOL);

        let throttle_id = rand::thread_rng().gen_range::<i64, _>(i64::MIN..i64::MAX);
        dao.mark_attempt_and_get_attempt_count(throttle_id, SystemTime::now())
            .unwrap();

        let mut job = ClearThrottleTableJob::new(env::testing::DB_THREAD_POOL.clone());

        assert_eq!(
            throttleable_attempts::table
                .find(throttle_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        for _ in 0..5 {
            dao.mark_attempt_and_get_attempt_count(
                rand::thread_rng().gen_range::<i64, _>(i64::MIN..i64::MAX),
                SystemTime::now(),
            )
            .unwrap();
        }

        assert!(
            throttleable_attempts::table
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap()
                > 0
        );

        job.execute().await.unwrap();

        assert_eq!(
            throttleable_attempts::table
                .count()
                .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );
    }
}
