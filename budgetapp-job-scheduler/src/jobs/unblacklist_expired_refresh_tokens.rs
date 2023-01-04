use budgetapp_utils::db::auth::Dao as AuthDao;
use budgetapp_utils::db::DbThreadPool;

use std::time::{Duration, SystemTime};

use crate::jobs::{Job, JobError};

pub struct UnblacklistExpiredRefreshTokensJob {
    pub job_frequency: Duration,
    db_thread_pool: DbThreadPool,
    last_run_time: SystemTime,
}

impl UnblacklistExpiredRefreshTokensJob {
    pub fn new(job_frequency: Duration, db_thread_pool: DbThreadPool) -> Self {
        Self {
            job_frequency,
            db_thread_pool,
            last_run_time: SystemTime::now(),
        }
    }
}

impl Job for UnblacklistExpiredRefreshTokensJob {
    fn name(&self) -> &'static str {
        "Unblacklist Expired Refresh Tokens"
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
        dao.clear_all_expired_refresh_tokens()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use budgetapp_utils::auth_token;
    use budgetapp_utils::db::user;
    use budgetapp_utils::models::blacklisted_token::NewBlacklistedToken;
    use budgetapp_utils::password_hasher;
    use budgetapp_utils::request_io::InputUser;
    use budgetapp_utils::schema::blacklisted_tokens::dsl::blacklisted_tokens;

    use diesel::{dsl, RunQueryDsl};
    use rand::Rng;
    use std::thread;

    use crate::env;

    #[test]
    fn test_last_run_time() {
        let before = SystemTime::now();

        thread::sleep(Duration::from_millis(1));
        let mut job = UnblacklistExpiredRefreshTokensJob::new(
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

        let mut user_dao = user::Dao::new(&env::db::DB_THREAD_POOL);

        user_dao
            .create_user(
                &new_user,
                &hash_params,
                vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
            )
            .unwrap();

        let user_id = user_dao.get_user_by_email(&new_user.email).unwrap().id;

        let token_params = auth_token::TokenParams {
            user_id: &user_id,
            user_email: &new_user.email,
            user_currency: &new_user.currency,
        };

        let pretend_expired_token = auth_token::generate_refresh_token(
            &token_params,
            Duration::from_secs(5),
            vec![32, 4, 23, 53].as_slice(),
        )
        .unwrap();
        let unexpired_token = auth_token::generate_refresh_token(
            &token_params,
            Duration::from_secs(5),
            vec![32, 4, 23, 53].as_slice(),
        )
        .unwrap();

        let expired_blacklisted = NewBlacklistedToken {
            token: &pretend_expired_token.to_string(),
            user_id,
            token_expiration_time: SystemTime::now() - Duration::from_secs(3600),
        };

        let unexpired_blacklisted = NewBlacklistedToken {
            token: &unexpired_token.to_string(),
            user_id,
            token_expiration_time: SystemTime::now() + Duration::from_secs(3600),
        };

        let mut db_connection = env::db::DB_THREAD_POOL.get().unwrap();
        dsl::insert_into(blacklisted_tokens)
            .values(&expired_blacklisted)
            .execute(&mut db_connection)
            .unwrap();
        dsl::insert_into(blacklisted_tokens)
            .values(&unexpired_blacklisted)
            .execute(&mut db_connection)
            .unwrap();

        let mut job = UnblacklistExpiredRefreshTokensJob::new(
            Duration::from_millis(1),
            env::db::DB_THREAD_POOL.clone(),
        );
        job.run_handler_func().unwrap();

        assert!(
            !auth_token::is_on_blacklist(&pretend_expired_token.to_string(), &mut dao).unwrap()
        );
        assert!(auth_token::is_on_blacklist(&unexpired_token.to_string(), &mut dao).unwrap());
    }
}
