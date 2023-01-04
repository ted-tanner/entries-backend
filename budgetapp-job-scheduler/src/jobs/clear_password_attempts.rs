use budgetapp_utils::db::auth::Dao as AuthDao;
use budgetapp_utils::db::DbThreadPool;

use std::time::{Duration, SystemTime};

use crate::jobs::{Job, JobError};

pub struct ClearPasswordAttemptsJob {
    pub job_frequency: Duration,
    pub attempts_lifetime: Duration,
    db_thread_pool: DbThreadPool,
    last_run_time: SystemTime,
}

impl ClearPasswordAttemptsJob {
    pub fn new(
        job_frequency: Duration,
        attempts_lifetime: Duration,
        db_thread_pool: DbThreadPool,
    ) -> Self {
        Self {
            job_frequency,
            attempts_lifetime,
            db_thread_pool,
            last_run_time: SystemTime::now(),
        }
    }
}

impl Job for ClearPasswordAttemptsJob {
    fn name(&self) -> &'static str {
        "Clear Password Attempts"
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
        let mut dao = AuthDao::new(&self.db_thread_pool);
        dao.clear_password_attempt_count(self.attempts_lifetime)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use budgetapp_utils::db::user;
    use budgetapp_utils::models::password_attempts::PasswordAttempts;
    use budgetapp_utils::password_hasher;
    use budgetapp_utils::request_io::InputUser;
    use budgetapp_utils::schema::password_attempts as password_attempts_fields;
    use budgetapp_utils::schema::password_attempts::dsl::password_attempts;

    use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
    use rand::Rng;
    use std::thread;

    use crate::env;

    #[test]
    fn test_last_run_time() {
        let before = SystemTime::now();

        thread::sleep(Duration::from_millis(1));
        let mut job = ClearPasswordAttemptsJob::new(
            Duration::from_millis(1),
            Duration::from_millis(1),
            env::db::DB_THREAD_POOL.clone(),
        );
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
    #[ignore]
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
                dao.get_and_increment_password_attempt_count(user.id, Duration::from_millis(1))
                    .unwrap();
            }
        }

        let mut db_connection = env::db::DB_THREAD_POOL.get().unwrap();

        for user_id in &user_ids {
            let user_password_attempts = password_attempts
                .filter(password_attempts_fields::user_id.eq(user_id))
                .first::<PasswordAttempts>(&mut db_connection);
            assert!(user_password_attempts.is_ok());
        }

        let mut job = ClearPasswordAttemptsJob::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            env::db::DB_THREAD_POOL.clone(),
        );

        job.run_handler_func().unwrap();

        for user_id in &user_ids {
            let user_password_attempts = password_attempts
                .filter(password_attempts_fields::user_id.eq(user_id))
                .first::<PasswordAttempts>(&mut db_connection);
            assert!(user_password_attempts.is_ok());
        }

        for user_id in &user_ids {
            dsl::update(password_attempts.filter(password_attempts_fields::user_id.eq(user_id)))
                .set(
                    password_attempts_fields::expiration_time.eq(SystemTime::now()
                        - Duration::from_secs(
                            env::CONF.clear_password_attempts_job.attempts_lifetime_mins * 60 + 1,
                        )),
                )
                .execute(&mut db_connection)
                .unwrap();
        }

        let mut job = ClearPasswordAttemptsJob::new(
            Duration::from_millis(1),
            Duration::from_millis(1),
            env::db::DB_THREAD_POOL.clone(),
        );
        job.run_handler_func().unwrap();

        for user_id in user_ids {
            let user_password_attempts = password_attempts
                .filter(password_attempts_fields::user_id.eq(user_id))
                .first::<PasswordAttempts>(&mut db_connection);
            assert!(user_password_attempts.is_err());
        }
    }
}
