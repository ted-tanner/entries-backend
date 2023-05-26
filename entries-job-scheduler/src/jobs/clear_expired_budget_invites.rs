use entries_utils::db::budget::Dao as BudgetDao;
use entries_utils::db::DbThreadPool;

use async_trait::async_trait;
use std::time::{Duration, SystemTime};

use crate::jobs::{Job, JobError};

// TODO: Test
pub struct ClearExpiredBudgetInvitesJob {
    pub job_frequency: Duration,
    db_thread_pool: DbThreadPool,
    is_running: bool,
    last_run_time: SystemTime,
}

impl ClearExpiredBudgetInvitesJob {
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
        "Clear Expired Budget Invites Job"
    }
}

#[async_trait]
impl Job for ClearExpiredBudgetInvitesJob {
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
        let mut dao = BudgetDao::new(&self.db_thread_pool);
        tokio::task::spawn_blocking(move || dao.delete_all_expired_invitations()).await??;
        Ok(())
    }
}
