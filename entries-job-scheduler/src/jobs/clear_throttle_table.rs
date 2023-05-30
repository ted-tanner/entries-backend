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

        let mut dao = ThrottleDao::new(&self.db_thread_pool);
        tokio::task::spawn_blocking(move || dao.clear_throttle_table()).await??;

        self.is_running = false;
        Ok(())
    }
}
