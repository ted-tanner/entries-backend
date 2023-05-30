use entries_utils::db::auth::Dao as AuthDao;
use entries_utils::db::DbThreadPool;

use async_trait::async_trait;

use crate::jobs::{Job, JobError};

pub struct UnblacklistExpiredTokensJob {
    db_thread_pool: DbThreadPool,
    is_running: bool,
}

impl UnblacklistExpiredTokensJob {
    pub fn new(db_thread_pool: DbThreadPool) -> Self {
        Self {
            db_thread_pool,
            is_running: false,
        }
    }
}

#[async_trait]
impl Job for UnblacklistExpiredTokensJob {
    fn name(&self) -> &'static str {
        "Unblacklist Expired Tokens"
    }

    fn is_ready(&self) -> bool {
        !self.is_running
    }

    async fn execute(&mut self) -> Result<(), JobError> {
        self.is_running = true;

        let mut dao = AuthDao::new(&self.db_thread_pool);
        tokio::task::spawn_blocking(move || dao.clear_all_expired_tokens()).await??;

        self.is_running = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use entries_utils::db::user;
    use entries_utils::models::blacklisted_token::NewBlacklistedToken;
    use entries_utils::request_io::InputUser;
    use entries_utils::schema::blacklisted_tokens::dsl::blacklisted_tokens;
    use entries_utils::token::auth_token::{AuthToken, AuthTokenType};
    use entries_utils::token::Token;

    use aes_gcm::{
        aead::{KeyInit, OsRng},
        Aes128Gcm,
    };
    use diesel::{dsl, RunQueryDsl};
    use rand::Rng;
    use std::time::{Duration, SystemTime};

    use crate::env;

    #[tokio::test]
    #[ignore]
    async fn test_execute() {
        let mut dao = AuthDao::new(&env::db::DB_THREAD_POOL);

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: Vec::new(),

            auth_string_salt: Vec::new(),
            auth_string_memory_cost_kib: 1024,
            auth_string_parallelism_factor: 1,
            auth_string_iters: 2,

            password_encryption_salt: Vec::new(),
            password_encryption_memory_cost_kib: 1024,
            password_encryption_parallelism_factor: 1,
            password_encryption_iters: 2,

            recovery_key_salt: Vec::new(),
            recovery_key_memory_cost_kib: 1024,
            recovery_key_parallelism_factor: 1,
            recovery_key_iters: 2,

            encryption_key_encrypted_with_password: Vec::new(),
            encryption_key_encrypted_with_recovery_key: Vec::new(),

            public_key: Vec::new(),

            preferences_encrypted: Vec::new(),
            user_keystore_encrypted: Vec::new(),

            acknowledge_agreement: true,
        };

        let mut user_dao = user::Dao::new(&env::db::DB_THREAD_POOL);

        let user_id = user_dao
            .create_user(&new_user, "Test", &Vec::new())
            .unwrap();
        user_dao.verify_user_creation(user_id).unwrap();

        let mut pretend_expired_token = AuthToken::new(
            user_id,
            &new_user.email,
            SystemTime::now() - Duration::from_secs(3600),
            AuthTokenType::Refresh,
        );

        let cipher = Aes128Gcm::new(&Aes128Gcm::generate_key(&mut OsRng));
        pretend_expired_token.encrypt(&cipher);

        let mut unexpired_token = AuthToken::new(
            user_id,
            &new_user.email,
            SystemTime::now() + Duration::from_secs(3600),
            AuthTokenType::Refresh,
        );

        unexpired_token.encrypt(&cipher);

        let pretend_expired_token = pretend_expired_token.sign_and_encode(&[0; 64]);
        let pretend_expired_token = AuthToken::from_str(&pretend_expired_token).unwrap();
        let pretend_expired_token_parts = pretend_expired_token.parts();
        let pretend_expired_token_signature =
            &pretend_expired_token_parts.as_ref().unwrap().signature;

        let expired_blacklisted = NewBlacklistedToken {
            token_signature: pretend_expired_token_signature,
            token_expiration: SystemTime::now() - Duration::from_secs(3600),
        };

        let unexpired_token = unexpired_token.sign_and_encode(&[0; 64]);
        let unexpired_token = AuthToken::from_str(&unexpired_token).unwrap();
        let unexpired_token_parts = unexpired_token.parts();
        let unexpired_token_signature = &unexpired_token_parts.as_ref().unwrap().signature;

        let unexpired_blacklisted = NewBlacklistedToken {
            token_signature: unexpired_token_signature,
            token_expiration: SystemTime::now() + Duration::from_secs(3600),
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

        let mut job = UnblacklistExpiredTokensJob::new(env::db::DB_THREAD_POOL.clone());
        job.execute().await.unwrap();

        assert!(!dao
            .check_is_token_on_blacklist_and_blacklist(pretend_expired_token_signature, 0)
            .unwrap());
        assert!(dao
            .check_is_token_on_blacklist_and_blacklist(unexpired_token_signature, 0)
            .unwrap());
    }
}
