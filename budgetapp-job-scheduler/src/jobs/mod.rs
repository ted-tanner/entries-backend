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
    fn run_handler_func(&mut self) -> Result<(), JobError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    use budgetapp_utils::db::auth::Dao as AuthDao;
    use budgetapp_utils::db::user;
    use budgetapp_utils::models::otp_attempts::OtpAttempts;
    use budgetapp_utils::password_hasher;
    use budgetapp_utils::request_io::InputUser;
    use budgetapp_utils::schema::otp_attempts as otp_attempts_fields;
    use budgetapp_utils::schema::otp_attempts::dsl::otp_attempts;

    use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use rand::Rng;

    use crate::env;

    #[test]
    fn test_job_ready() {
        let mut job = clear_otp_attempts::ClearOtpAttempts::new();

        job.set_last_run_time(SystemTime::now() + Duration::from_secs(5));
        assert!(!job.ready());

        job.set_last_run_time(SystemTime::now() - Duration::from_secs(86400 * 366));
        assert!(job.ready());

        job.set_last_run_time(SystemTime::now() + Duration::from_secs(5));
        assert!(!job.ready());
    }

    #[ignore]
    #[test]
    fn test_job_execute() {
        let mut dao = AuthDao::new(&env::db::DB_THREAD_POOL);

        let mut user_ids = Vec::new();

        for _ in 0..3 {
            let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

            let new_user = InputUser {
                email: format!("test_user{}@test.com", &user_number),
                password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
                first_name: format!("Test-{}", &user_number),
                last_name: format!("User-{}", &user_number),
                date_of_birth: SystemTime::UNIX_EPOCH
                    + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
                currency: String::from("USD"),
            };

            let hash_params = password_hasher::HashParams {
                salt_len: 16,
                hash_len: 32,
                hash_iterations: 2,
                hash_mem_size_kib: 128,
                hash_lanes: 2,
            };

            let user = user::Dao::new(&env::db::DB_THREAD_POOL)
                .create_user(
                    &new_user,
                    &hash_params,
                    vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
                )
                .unwrap();

            user_ids.push(user.id);

            for _ in 0..rand::thread_rng().gen_range::<u32, _>(1..4) {
                dao.get_and_increment_otp_verification_count(user.id, Duration::from_millis(1))
                    .unwrap();
            }
        }

        let mut db_connection = env::db::DB_THREAD_POOL.get().unwrap();

        // Ensure rows are in the table before clearing
        for user_id in user_ids.clone() {
            let user_otp_attempts = otp_attempts
                .filter(otp_attempts_fields::user_id.eq(user_id))
                .first::<OtpAttempts>(&mut db_connection);
            assert!(user_otp_attempts.is_ok());
        }

        let mut job = ClearOtpAttempts::new();
        job.set_last_run_time(SystemTime::now() + Duration::from_secs(5));

        assert!(
            matches!(job.execute().unwrap_err(), JobError::NotReady),
            "Job should not have been ready. It's last_run_time was in the future."
        );

        for user_id in user_ids.clone() {
            let user_otp_attempts = otp_attempts
                .filter(otp_attempts_fields::user_id.eq(user_id))
                .first::<OtpAttempts>(&mut db_connection);
            assert!(user_otp_attempts.is_ok());
        }

        job.set_last_run_time(SystemTime::now() - Duration::from_secs(86400 * 366));
        job.execute().unwrap();

        // Ensure rows have been removed
        for user_id in user_ids {
            let user_otp_attempts = otp_attempts
                .filter(otp_attempts_fields::user_id.eq(user_id))
                .first::<OtpAttempts>(&mut db_connection);
            assert!(user_otp_attempts.is_err());
        }
    }
}
