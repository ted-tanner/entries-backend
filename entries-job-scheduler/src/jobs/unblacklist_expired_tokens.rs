use entries_common::db::auth::Dao as AuthDao;
use entries_common::db::DbThreadPool;

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

        let dao = AuthDao::new(&self.db_thread_pool);
        tokio::task::spawn_blocking(move || dao.clear_all_expired_tokens()).await??;

        self.is_running = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use entries_common::db::user;
    use entries_common::messages::NewUser;
    use entries_common::models::blacklisted_token::NewBlacklistedToken;
    use entries_common::schema::blacklisted_tokens::dsl::blacklisted_tokens;
    use entries_common::threadrand::SecureRng;
    use entries_common::token::auth_token::{AuthToken, AuthTokenType, NewAuthTokenClaims};
    use entries_common::token::Token;

    use diesel::{dsl, RunQueryDsl};
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    use crate::env;

    #[tokio::test]
    #[ignore]
    async fn test_execute() {
        let user_number = SecureRng::next_u128();

        let public_key_id = Uuid::now_v7();
        let new_user = NewUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: Vec::new(),

            auth_string_hash_salt: Vec::new(),
            auth_string_hash_mem_cost_kib: 1024,
            auth_string_hash_threads: 1,
            auth_string_hash_iterations: 2,

            password_encryption_key_salt: Vec::new(),
            password_encryption_key_mem_cost_kib: 1024,
            password_encryption_key_threads: 1,
            password_encryption_key_iterations: 2,

            recovery_key_hash_salt: Vec::new(),
            recovery_key_hash_mem_cost_kib: 1024,
            recovery_key_hash_threads: 1,
            recovery_key_hash_iterations: 2,

            encryption_key_encrypted_with_password: Vec::new(),
            encryption_key_encrypted_with_recovery_key: Vec::new(),

            public_key_id: public_key_id.into(),
            public_key: Vec::new(),

            preferences_encrypted: Vec::new(),
            preferences_version_nonce: SecureRng::next_i64(),
            user_keystore_encrypted: Vec::new(),
            user_keystore_version_nonce: SecureRng::next_i64(),
        };

        let user_dao = user::Dao::new(&env::testing::DB_THREAD_POOL);

        let user_id = user_dao
            .create_user(
                &new_user.email,
                "",
                &new_user.auth_string_hash_salt,
                new_user.auth_string_hash_mem_cost_kib,
                new_user.auth_string_hash_threads,
                new_user.auth_string_hash_iterations,
                &new_user.password_encryption_key_salt,
                new_user.password_encryption_key_mem_cost_kib,
                new_user.password_encryption_key_threads,
                new_user.password_encryption_key_iterations,
                &new_user.recovery_key_hash_salt,
                new_user.recovery_key_hash_mem_cost_kib,
                new_user.recovery_key_hash_threads,
                new_user.recovery_key_hash_iterations,
                &new_user.encryption_key_encrypted_with_password,
                &new_user.encryption_key_encrypted_with_recovery_key,
                public_key_id,
                &new_user.public_key,
                &new_user.preferences_encrypted,
                new_user.preferences_version_nonce,
                &new_user.user_keystore_encrypted,
                new_user.user_keystore_version_nonce,
                &Vec::new(),
            )
            .unwrap();
        user_dao.verify_user_creation(user_id).unwrap();

        let pretend_expired_token_claims = NewAuthTokenClaims {
            user_id,
            user_email: &new_user.email,
            expiration: (SystemTime::now() - Duration::from_secs(3600))
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            token_type: AuthTokenType::Refresh,
        };

        let pretend_expired_token = AuthToken::sign_new(pretend_expired_token_claims, &[0; 64]);

        let unexpired_token_claims = NewAuthTokenClaims {
            user_id,
            user_email: &new_user.email,
            expiration: (SystemTime::now() + Duration::from_secs(3600))
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            token_type: AuthTokenType::Refresh,
        };

        let unexpired_token = AuthToken::sign_new(unexpired_token_claims, &[0; 64]);

        let pretend_expired_token = AuthToken::decode(&pretend_expired_token).unwrap();

        let expired_blacklisted = NewBlacklistedToken {
            token_signature: &pretend_expired_token.signature,
            token_expiration: SystemTime::now() - Duration::from_secs(3600),
        };

        let unexpired_token = AuthToken::decode(&unexpired_token).unwrap();

        let unexpired_blacklisted = NewBlacklistedToken {
            token_signature: &unexpired_token.signature,
            token_expiration: SystemTime::now() + Duration::from_secs(3600),
        };

        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();
        dsl::insert_into(blacklisted_tokens)
            .values(&expired_blacklisted)
            .execute(&mut db_connection)
            .unwrap();
        dsl::insert_into(blacklisted_tokens)
            .values(&unexpired_blacklisted)
            .execute(&mut db_connection)
            .unwrap();

        let mut job = UnblacklistExpiredTokensJob::new(env::testing::DB_THREAD_POOL.clone());
        job.execute().await.unwrap();

        let dao = AuthDao::new(&env::testing::DB_THREAD_POOL);

        assert!(!dao
            .check_is_token_on_blacklist_and_blacklist(&pretend_expired_token.signature, 0)
            .unwrap());
        assert!(dao
            .check_is_token_on_blacklist_and_blacklist(&unexpired_token.signature, 0)
            .unwrap());
    }
}
