mod clear_otp_attempts;
mod clear_password_attempts;
mod unblacklist_expired_refresh_tokens;

pub use clear_otp_attempts::ClearOtpAttempts;
pub use clear_password_attempts::ClearPasswordAttempts;
pub use unblacklist_expired_refresh_tokens::UnblacklistExpiredRefreshTokens;

use budgetapp_utils::db::DaoError;

use std::fmt;
use std::time::{Duration, SystemTime};

#[derive(Debug)]
pub enum JobError {
    DaoFailure(DaoError),
    NotReady,
}

impl fmt::Display for JobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobError::DaoFailure(e) => {
                write!(f, "JobError: {}", e)
            }
            JobError::NotReady => {
                write!(f, "JobError: Attempted execution before job was ready")
            }
        }
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
    fn run_handler_func(&self) -> Result<(), JobError>;
}
