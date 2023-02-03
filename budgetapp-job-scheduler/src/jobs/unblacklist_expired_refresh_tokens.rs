use budgetapp_utils::db::auth::Dao as AuthDao;
use budgetapp_utils::db::DbThreadPool;

use async_trait::async_trait;
use std::time::{Duration, SystemTime};

use crate::jobs::{Job, JobError};

pub struct UnblacklistExpiredRefreshTokensJob {
    pub job_frequency: Duration,
    db_thread_pool: DbThreadPool,
    is_running: bool,
    last_run_time: SystemTime,
}

impl UnblacklistExpiredRefreshTokensJob {
    pub fn new(job_frequency: Duration, db_thread_pool: DbThreadPool) -> Self {
        Self {
            job_frequency,
            db_thread_pool,
            is_running: false,
            last_run_time: SystemTime::now(),
        }
    }
}

#[async_trait]
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

    fn is_running(&self) -> bool {
        self.is_running
    }

    fn set_running_state_not_running(&mut self) {
        self.is_running = false;
    }

    fn set_running_state_running(&mut self) {
        self.is_running = true;
    }

    async fn run_handler_func(&mut self) -> Result<(), JobError> {
        let mut dao = AuthDao::new(&self.db_thread_pool);

        tokio::task::spawn_blocking(move || dao.clear_all_expired_refresh_tokens()).await??;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use budgetapp_utils::auth_token;
    use budgetapp_utils::db::user;
    use budgetapp_utils::models::blacklisted_token::NewBlacklistedToken;
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

    #[tokio::test]
    #[ignore]
    async fn test_run_handler_fun() {
        let mut dao = AuthDao::new(&env::db::DB_THREAD_POOL);

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: String::new(),

            auth_string_salt: String::new(),
            auth_string_iters: 1000000,

            password_encryption_salt: String::new(),
            password_encryption_iters: 5000000,

            recovery_key_salt: String::new(),
            recovery_key_iters: 10000000,

            encryption_key_user_password_encrypted: String::new(),
            encryption_key_recovery_key_encrypted: String::new(),

            public_rsa_key: String::new(),
            private_rsa_key_encrypted: String::new(),

            preferences_encrypted: String::new(),
        };

        let user_id = user::Dao::new(&env::db::DB_THREAD_POOL)
            .create_user(&new_user, "Test")
            .unwrap();

        let token_params = auth_token::TokenParams {
            user_id: &user_id,
            user_email: &new_user.email,
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
        job.run_handler_func().await.unwrap();

        assert!(
            !auth_token::is_on_blacklist(&pretend_expired_token.to_string(), &mut dao).unwrap()
        );
        assert!(auth_token::is_on_blacklist(&unexpired_token.to_string(), &mut dao).unwrap());
    }
}
