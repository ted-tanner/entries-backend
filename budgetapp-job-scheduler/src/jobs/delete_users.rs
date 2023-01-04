use budgetapp_utils::db::user::Dao as UserDao;
use budgetapp_utils::db::DbThreadPool;

use std::time::{Duration, SystemTime};

use crate::jobs::{Job, JobError};

// TODO: Test
pub struct DeleteUsersJob {
    pub job_frequency: Duration,
    db_thread_pool: DbThreadPool,
    last_run_time: SystemTime,
}

impl DeleteUsersJob {
    pub fn new(job_frequency: Duration, db_thread_pool: DbThreadPool) -> Self {
        Self {
            job_frequency,
            db_thread_pool,
            last_run_time: SystemTime::now(),
        }
    }
}

impl Job for DeleteUsersJob {
    fn name(&self) -> &'static str {
        "Delete Users"
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

    fn run_handler_func(&mut self) -> Result<(), JobError> {
        let mut dao = UserDao::new(&self.db_thread_pool);

        let users_ready_for_deletion = dao.get_all_users_ready_for_deletion()?;

        let mut last_error: Option<_> = None;
        for user in &users_ready_for_deletion {
            if let Err(e) = dao.delete_user(user) {
                log::error!("User deletion failed for user {}: {}", &user.user_id, e);
                last_error = Some(e);
            }
        }

        if let Some(e) = last_error {
            return Err(e.into());
        }

        Ok(())
    }
}
