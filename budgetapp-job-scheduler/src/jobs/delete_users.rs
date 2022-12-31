use budgetapp_utils::db::user::Dao as UserDao;

use std::time::{Duration, SystemTime};

use crate::env;
use crate::jobs::{Job, JobError};

// TODO: Test
pub struct DeleteUsersJob {
    last_run_time: SystemTime,
}

impl DeleteUsersJob {
    pub fn new() -> Self {
        Self {
            last_run_time: SystemTime::now(),
        }
    }
}

impl Job for DeleteUsersJob {
    fn name(&self) -> &'static str {
        "Delete Users"
    }

    fn run_frequency(&self) -> Duration {
        Duration::from_secs(env::CONF.delete_users_job.job_frequency_secs)
    }

    fn last_run_time(&self) -> SystemTime {
        self.last_run_time
    }

    fn set_last_run_time(&mut self, time: SystemTime) {
        self.last_run_time = time
    }

    fn run_handler_func(&mut self) -> Result<(), JobError> {
        let mut dao = UserDao::new(&env::db::DB_THREAD_POOL);

        let users_ready_for_deletion = dao.get_all_users_ready_for_deletion()?;

        let mut last_error: Option<_> = None;
        for user in users_ready_for_deletion {
            if let Err(e) = dao.delete_user(user) {
                log::error!("User deletion failed: {}", e);
                last_error = Some(e);
            }
        }

        if let Some(e) = last_error {
            return Err(e.into());
        }

        Ok(())
    }
}
