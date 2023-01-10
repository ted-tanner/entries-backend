use budgetapp_utils::db::user::Dao as UserDao;
use budgetapp_utils::db::DbThreadPool;

use async_trait::async_trait;
use std::time::{Duration, SystemTime};

use crate::jobs::{Job, JobError};

pub struct ClearOldNotificationsJob {
    pub job_frequency: Duration,
    pub max_notification_age: Duration,

    db_thread_pool: DbThreadPool,
    is_running: bool,
    last_run_time: SystemTime,
}

impl ClearOldNotificationsJob {
    pub fn new(
        job_frequency: Duration,
        max_notification_age: Duration,
        db_thread_pool: DbThreadPool,
    ) -> Self {
        Self {
            job_frequency,
            max_notification_age,
            db_thread_pool,
            is_running: false,
            last_run_time: SystemTime::now(),
        }
    }
}

#[async_trait]
impl Job for ClearOldNotificationsJob {
    fn name(&self) -> &'static str {
        "Clear Old User Notifications"
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

    async fn run_handler_func(&mut self) -> Result<(), JobError> {
        let max_age = self.max_notification_age;
        let mut dao = UserDao::new(&self.db_thread_pool);

        tokio::task::spawn_blocking(move || dao.clear_old_notifications(max_age)).await??;

        Ok(())
    }
}
