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

    fn run_handler_func(&mut self) -> Result<(), JobError> {
        let mut dao = AuthDao::new(&env::db::DB_THREAD_POOL);

        if let Err(e) = dao.clear_otp_verification_count() {
            return Err(JobError::DaoFailure(e));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use budgetapp_utils::db::user;
    use budgetapp_utils::password_hasher;
    use budgetapp_utils::request_io::InputUser;
    use budgetapp_utils::models::otp_attempts::OtpAttempts;
    use budgetapp_utils::schema::otp_attempts as otp_attempts_fields;
    use budgetapp_utils::schema::otp_attempts::dsl::otp_attempts;

    use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use rand::Rng;
    use std::thread;

    #[test]
    fn test_last_run_time() {
        let before = SystemTime::now();
        
        thread::sleep(Duration::from_millis(1));
        let mut job = ClearOtpAttempts::new();
        thread::sleep(Duration::from_millis(1));
        
        assert!(job.last_run_time() > before);
        assert!(job.last_run_time() < SystemTime::now());

        let before = SystemTime::now();
        
        thread::sleep(Duration::from_millis(1));
        job.set_last_run_time(SystemTime::now());
        thread::sleep(Duration::from_millis(1));
        
        assert!(job.last_run_time() > before);
        assert!(job.last_run_time() < SystemTime::now());
    }
    
    #[test]
    fn test_run_handler_fun() {
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
                dao.get_and_increment_otp_verification_count(user.id)
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
        job.run_handler_func().unwrap();

        // Ensure rows have been removed
        for user_id in user_ids {
            let user_otp_attempts = otp_attempts
                .filter(otp_attempts_fields::user_id.eq(user_id))
                .first::<OtpAttempts>(&mut db_connection);
            assert!(user_otp_attempts.is_err());
        }
    }
}
