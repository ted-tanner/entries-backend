use budgetapp_utils::db::auth::Dao as AuthDao;
use budgetapp_utils::db::DbThreadPool;

use async_trait::async_trait;
use std::time::{Duration, SystemTime};

use crate::jobs::{Job, JobError};

pub struct UnblacklistExpiredTokensJob {
    pub job_frequency: Duration,
    db_thread_pool: DbThreadPool,
    is_running: bool,
    last_run_time: SystemTime,
}

impl UnblacklistExpiredTokensJob {
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
impl Job for UnblacklistExpiredTokensJob {
    fn name(&self) -> &'static str {
        "Unblacklist Expired Tokens"
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

        tokio::task::spawn_blocking(move || dao.clear_all_expired_tokens()).await??;

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

    use aes_gcm::{
        aead::{KeyInit, OsRng},
        Aes128Gcm,
    };
    use diesel::{dsl, RunQueryDsl};
    use rand::Rng;
    use std::thread;

    use crate::env;

    #[test]
    fn test_last_run_time() {
        let before = SystemTime::now();

        thread::sleep(Duration::from_millis(1));
        let mut job = UnblacklistExpiredTokensJob::new(
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

            auth_string_salt: Vec::new(),
            auth_string_iters: 1000000,

            password_encryption_salt: Vec::new(),
            password_encryption_iters: 5000000,

            recovery_key_salt: Vec::new(),
            recovery_key_iters: 10000000,

            encryption_key_encrypted_with_password: Vec::new(),
            encryption_key_encrypted_with_recovery_key: Vec::new(),

            public_rsa_key: Vec::new(),

            preferences_encrypted: Vec::new(),
            user_keystore_encrypted: Vec::new(),
        };

        let mut user_dao = user::Dao::new(&env::db::DB_THREAD_POOL);

        let user_id = user_dao.create_user(new_user.clone(), "Test").unwrap();
        user_dao.verify_user_creation(user_id).unwrap();

        let token_params = auth_token::TokenParams {
            user_id: user_id,
            user_email: &new_user.email,
        };

        let cipher = Aes128Gcm::new(&Aes128Gcm::generate_key(&mut OsRng));

        let pretend_expired_token = auth_token::generate_token(
            &token_params,
            auth_token::TokenType::Refresh,
            Duration::from_secs(5),
            &[0u8; 64],
            &cipher,
        )
        .unwrap();

        let pretend_claims = auth_token::TokenClaims {
            exp: 64,
            uid: user_id,
            eml: String::from("Test"),
            typ: 2,
        };

        let unexpired_token = auth_token::generate_token(
            &token_params,
            auth_token::TokenType::Refresh,
            Duration::from_secs(5),
            &[0u8; 64],
            &cipher,
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

        let mut job = UnblacklistExpiredTokensJob::new(
            Duration::from_millis(1),
            env::db::DB_THREAD_POOL.clone(),
        );
        job.run_handler_func().await.unwrap();

        assert!(!dao
            .check_is_token_on_blacklist_and_blacklist(
                &pretend_expired_token.to_string(),
                pretend_claims.clone()
            )
            .unwrap());
        assert!(dao
            .check_is_token_on_blacklist_and_blacklist(&unexpired_token.to_string(), pretend_claims)
            .unwrap());
    }
}
