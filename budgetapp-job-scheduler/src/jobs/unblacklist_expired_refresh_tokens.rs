use budgetapp_utils::db::auth::Dao as AuthDao;

use std::time::{Duration, SystemTime};

use crate::env;
use crate::jobs::{Job, JobError};

pub struct UnblacklistExpiredRefreshTokens {
    last_run_time: SystemTime,
}

impl UnblacklistExpiredRefreshTokens {
    pub fn new() -> Self {
        Self {
            last_run_time: SystemTime::now(),
        }
    }
}

impl Job for UnblacklistExpiredRefreshTokens {
    fn name(&self) -> &'static str {
        "Unblacklist Expired Refresh Tokens"
    }

    fn run_frequency(&self) -> Duration {
        Duration::from_secs(
            env::CONF
                .unblacklist_expired_refresh_tokens_job
                .job_frequency_secs,
        )
    }

    fn last_run_time(&self) -> SystemTime {
        self.last_run_time
    }

    fn set_last_run_time(&mut self, time: SystemTime) {
        self.last_run_time = time
    }

    fn run_handler_func(&self) -> Result<(), JobError> {
        let mut dao = AuthDao::new(&env::db::DB_THREAD_POOL);

        if let Err(e) = dao.clear_all_expired_refresh_tokens() {
            return Err(JobError::DaoFailure(e));
        }

        Ok(())
    }
}
