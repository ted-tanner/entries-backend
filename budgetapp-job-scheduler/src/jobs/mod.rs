mod clear_unverified_users;
mod delete_users;
mod unblacklist_expired_tokens;

pub use clear_unverified_users::ClearUnverifiedUsersJob;
pub use delete_users::DeleteUsersJob;
pub use unblacklist_expired_tokens::UnblacklistExpiredTokensJob;

use budgetapp_utils::db::job_registry::Dao as JobRegistryDao;
use budgetapp_utils::db::{DaoError, DbThreadPool};

use async_trait::async_trait;
use std::fmt;
use std::time::{Duration, SystemTime};
use tokio::task::JoinError;

#[derive(Debug)]
pub enum JobError {
    DaoFailure(Option<DaoError>),
    ConcurrencyError(JoinError),
    NotReady,
}

impl fmt::Display for JobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobError::DaoFailure(e) => {
                if let Some(inner_err) = e {
                    write!(f, "JobError: {inner_err}")
                } else {
                    write!(f, "JobError: DaoFailure")
                }
            }
            JobError::ConcurrencyError(e) => {
                write!(f, "JobError: ConcurrencyError: {e}")
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

impl From<JoinError> for JobError {
    fn from(e: JoinError) -> Self {
        JobError::ConcurrencyError(e)
    }
}

#[async_trait]
pub trait Job: Send {
    fn name(&self) -> &'static str;
    fn run_frequency(&self) -> Duration;
    fn last_run_time(&self) -> SystemTime;
    fn set_last_run_time(&mut self, time: SystemTime);

    fn is_running(&self) -> bool;
    fn set_running_state_not_running(&mut self);
    fn set_running_state_running(&mut self);

    fn get_db_thread_pool_ref(&self) -> &DbThreadPool;

    fn ready(&self) -> bool {
        !self.is_running() && SystemTime::now() > self.last_run_time() + self.run_frequency()
    }

    async fn execute(&mut self) -> Result<(), JobError> {
        if self.ready() {
            self.set_last_run_time(SystemTime::now());

            // If the job runs more frequently than every two minutes, don't record it. The
            // time is recorded to allow jobs to be run sooner upon startup if they haven't
            // been run in the environment recently. This doesn't matter for frequently-run
            // jobs.
            if self.run_frequency() >= Duration::from_secs(60 * 2) {
                self.record_run().await?;
            }

            self.set_running_state_running();
            let res = self.run_handler_func().await;
            self.set_running_state_not_running();

            res
        } else {
            Err(JobError::NotReady)
        }
    }

    async fn record_run(&mut self) -> Result<(), JobError> {
        let mut dao = JobRegistryDao::new(self.get_db_thread_pool_ref());
        let name = self.name();

        tokio::task::spawn_blocking(move || {
            dao.set_job_last_run_timestamp(name, SystemTime::now())
        })
        .await??;

        Ok(())
    }

    async fn run_handler_func(&mut self) -> Result<(), JobError>;
}

#[cfg(test)]
pub mod tests {
    use crate::env;

    use super::*;

    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    pub struct MockJob {
        pub last_run_time: SystemTime,
        pub is_running: bool,
        pub run_frequency: Duration,
        pub runs: Arc<Mutex<usize>>,
    }

    impl MockJob {
        pub fn new(run_frequency: Duration) -> Self {
            Self {
                last_run_time: SystemTime::now(),
                is_running: false,
                run_frequency,
                runs: Arc::new(Mutex::new(0)),
            }
        }
    }

    #[async_trait]
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
            &env::db::DB_THREAD_POOL
        }

        async fn run_handler_func(&mut self) -> Result<(), JobError> {
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

    #[tokio::test]
    async fn test_job_execute() {
        let mut job = MockJob::new(Duration::from_millis(10));
        let job_run_count = Arc::clone(&job.runs);
        assert_eq!(*job_run_count.lock().unwrap(), 0);

        job.set_last_run_time(SystemTime::now() + Duration::from_secs(5));
        assert!(
            matches!(job.execute().await.unwrap_err(), JobError::NotReady),
            "Job should not have been ready. Its last_run_time was in the future."
        );

        job.set_last_run_time(SystemTime::now() - Duration::from_secs(1));
        job.execute().await.unwrap();

        assert_eq!(*job_run_count.lock().unwrap(), 1);
    }

    // TODO: Test record_run()
    // TODO: Test get_db_thread_pool_ref()
}
