mod clear_expired_container_invites;
mod clear_expired_otps;
mod clear_old_user_deletion_requests;
mod clear_unverified_users;
mod delete_users;
mod unblacklist_expired_tokens;

pub use clear_expired_container_invites::ClearExpiredContainerInvitesJob;
pub use clear_expired_otps::ClearExpiredOtpsJob;
pub use clear_old_user_deletion_requests::ClearOldUserDeletionRequestsJob;
pub use clear_unverified_users::ClearUnverifiedUsersJob;
pub use delete_users::DeleteUsersJob;
pub use unblacklist_expired_tokens::UnblacklistExpiredTokensJob;

use entries_common::db::DaoError;

use async_trait::async_trait;
use std::fmt;
use tokio::task::JoinError;

#[derive(Debug)]
pub enum JobError {
    DaoFailure(Option<DaoError>),
    ConcurrencyError(JoinError),
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
    fn is_ready(&self) -> bool;
    async fn execute(&mut self) -> Result<(), JobError>;
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use async_trait::async_trait;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    pub struct MockJob {
        pub is_running: bool,
        pub runs: Arc<Mutex<usize>>,
    }

    impl MockJob {
        pub fn new() -> Self {
            Self {
                is_running: false,
                runs: Arc::new(Mutex::new(0)),
            }
        }
    }

    #[async_trait]
    impl Job for MockJob {
        fn name(&self) -> &'static str {
            "Mock"
        }

        fn is_ready(&self) -> bool {
            !self.is_running
        }

        async fn execute(&mut self) -> Result<(), JobError> {
            self.is_running = true;

            *self.runs.lock().await += 1;

            self.is_running = false;
            Ok(())
        }
    }

    #[test]
    fn test_job_ready() {
        let mut job = MockJob::new();

        assert!(job.is_ready());

        job.is_running = true;

        assert!(!job.is_ready());

        job.is_running = false;

        assert!(job.is_ready());
    }

    #[tokio::test]
    async fn test_job_execute() {
        let mut job = MockJob::new();
        let job_run_count = Arc::clone(&job.runs);
        assert_eq!(*job_run_count.lock().await, 0);

        job.execute().await.unwrap();

        assert_eq!(*job_run_count.lock().await, 1);
    }
}
