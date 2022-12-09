use budgetapp_utils::db::auth::Dao as AuthDao;

use std::time::{Duration, SystemTime};

use crate::env;
use crate::jobs::{Job, JobError};

pub struct ClearOtpAttempts {
    last_run_time: SystemTime,
}

impl ClearOtpAttempts {
    pub fn new() -> Self {
        Self {
            last_run_time: SystemTime::now(),
        }
    }
}

impl Job for ClearOtpAttempts {
    fn name(&self) -> &'static str {
        "Clear OTP Attempts"
    }

    fn run_frequency(&self) -> Duration {
        Duration::from_secs(env::CONF.clear_otp_attempts_job.job_frequency_secs)
    }

    fn last_run_time(&self) -> SystemTime {
        self.last_run_time
    }

    fn set_last_run_time(&mut self, time: SystemTime) {
        self.last_run_time = time
    }

    fn run_handler_func(&self) -> Result<(), JobError> {
        let mut dao = AuthDao::new(&env::db::DB_THREAD_POOL);

        if let Err(e) = dao.clear_otp_verification_count() {
            return Err(JobError::DaoFailure(e));
        }

        Ok(())
    }
}
