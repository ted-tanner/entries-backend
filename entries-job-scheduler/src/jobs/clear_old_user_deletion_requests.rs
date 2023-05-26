use entries_utils::db::user::Dao as UserDao;
use entries_utils::db::DbThreadPool;

use async_trait::async_trait;
use std::time::{Duration, SystemTime};

use crate::jobs::{Job, JobError};

// TODO: Test
pub struct ClearOldUserDeletionRequestsJob {
    pub job_frequency: Duration,
    db_thread_pool: DbThreadPool,
    is_running: bool,
    last_run_time: SystemTime,
}

impl ClearOldUserDeletionRequestsJob {
    pub fn new(
        job_frequency: Duration,
        last_run_time: SystemTime,
        db_thread_pool: DbThreadPool,
    ) -> Self {
        Self {
            job_frequency,
            db_thread_pool,
            is_running: false,
            last_run_time,
        }
    }

    pub fn name() -> &'static str {
        "Clear Old User Deletion Requests"
    }
}

#[async_trait]
impl Job for ClearOldUserDeletionRequestsJob {
    fn name(&self) -> &'static str {
        Self::name()
    }

    fn run_frequency(&self) -> Duration {
        self.job_frequency
    }

    fn last_run_time(&self) -> SystemTime {
        self.last_run_time
    }

    fn set_last_run_time(&mut self, time: SystemTime) {
        self.last_run_time = time
    }

    fn is_running(&self) -> bool {
        self.is_running
    }

    fn set_running_state_not_running(&mut self) {
        self.is_running = false;
    }

    fn set_running_state_running(&mut self) {
        self.is_running = true;
    }

    fn get_db_thread_pool_ref(&self) -> &DbThreadPool {
        &self.db_thread_pool
    }

    async fn run_handler_func(&mut self) -> Result<(), JobError> {
        let mut dao = UserDao::new(&self.db_thread_pool);
        tokio::task::spawn_blocking(move || dao.delete_old_user_deletion_requests()).await??;
        Ok(())
    }
}
