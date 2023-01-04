mod clear_otp_attempts;
mod clear_password_attempts;
mod delete_users;
mod unblacklist_expired_refresh_tokens;

pub use clear_otp_attempts::ClearOtpAttemptsJob;
pub use clear_password_attempts::ClearPasswordAttemptsJob;
pub use delete_users::DeleteUsersJob;
pub use unblacklist_expired_refresh_tokens::UnblacklistExpiredRefreshTokensJob;

use budgetapp_utils::db::DaoError;

use std::fmt;
use std::time::{Duration, SystemTime};

#[derive(Debug)]
pub enum JobError {
    DaoFailure(Option<DaoError>),
    NotReady,
}

impl fmt::Display for JobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobError::DaoFailure(e) => {
                if let Some(inner_err) = e {
                    write!(f, "JobError: {}", inner_err)
                } else {
                    write!(f, "JobError: DaoFailure")
                }
            }
            JobError::NotReady => {
                write!(f, "JobError: Attempted execution before job was ready")
            }
        }
    }
}

impl From<DaoError> for JobError {
    fn from(e: DaoError) -> Self {
        JobError::DaoFailure(Some(e))
    }
}

pub trait Job: Send {
    fn name(&self) -> &'static str;
    fn run_frequency(&self) -> Duration;
    fn last_run_time(&self) -> SystemTime;

    fn ready(&self) -> bool {
        SystemTime::now() > self.last_run_time() + self.run_frequency()
    }

    fn execute(&mut self) -> Result<(), JobError> {
        if self.ready() {
            let res = self.run_handler_func();
            self.set_last_run_time(SystemTime::now());

            res
        } else {
            Err(JobError::NotReady)
        }
    }

    fn set_last_run_time(&mut self, time: SystemTime);
    fn run_handler_func(&mut self) -> Result<(), JobError>;
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    pub struct MockJob {
        pub last_run_time: SystemTime,
        pub run_frequency: Duration,
        pub runs: Arc<Mutex<usize>>,
    }

    impl MockJob {
        pub fn new(run_frequency: Duration) -> Self {
            Self {
                last_run_time: SystemTime::now(),
                run_frequency,
                runs: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl Job for MockJob {
        fn name(&self) -> &'static str {
            "Mock"
        }

        fn run_frequency(&self) -> Duration {
            self.run_frequency
        }

        fn last_run_time(&self) -> SystemTime {
            self.last_run_time
        }

        fn set_last_run_time(&mut self, time: SystemTime) {
            self.last_run_time = time;
        }

        fn run_handler_func(&mut self) -> Result<(), JobError> {
            *self.runs.lock().unwrap() += 1;
            Ok(())
        }
    }

    #[test]
    fn test_job_ready() {
        let mut job = MockJob::new(Duration::from_secs(10));

        job.set_last_run_time(SystemTime::now() + Duration::from_secs(5));
        assert!(!job.ready());

        job.set_last_run_time(SystemTime::now() - Duration::from_secs(25));
        assert!(job.ready());

        job.set_last_run_time(SystemTime::now() + Duration::from_secs(5));
        assert!(!job.ready());
    }

    #[test]
    fn test_job_execute() {
        let mut job = MockJob::new(Duration::from_millis(10));
        let job_run_count = Arc::clone(&job.runs);
        assert_eq!(*job_run_count.lock().unwrap(), 0);

        job.set_last_run_time(SystemTime::now() + Duration::from_secs(5));
        assert!(
            matches!(job.execute().unwrap_err(), JobError::NotReady),
            "Job should not have been ready. Its last_run_time was in the future."
        );

        job.set_last_run_time(SystemTime::now() - Duration::from_secs(1));
        job.execute().unwrap();

        assert_eq!(*job_run_count.lock().unwrap(), 1);
    }
}
