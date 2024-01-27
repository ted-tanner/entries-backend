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

        let dao = AuthDao::new(&self.db_thread_pool);
        tokio::task::spawn_blocking(move || dao.clear_all_expired_tokens()).await??;

        self.is_running = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use entries_utils::db::user;
    use entries_utils::messages::NewUser;
    use entries_utils::models::blacklisted_token::NewBlacklistedToken;
    use entries_utils::schema::blacklisted_tokens::dsl::blacklisted_tokens;
    use entries_utils::token::auth_token::{AuthToken, AuthTokenType, NewAuthTokenClaims};
    use entries_utils::token::Token;

    use diesel::{dsl, RunQueryDsl};
    use rand::Rng;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    use crate::env;

    #[tokio::test]
    #[ignore]
    async fn test_execute() {
        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let public_key_id = Uuid::new_v4();
        let new_user = NewUser {
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

            public_key_id: public_key_id.into(),
            public_key: Vec::new(),

            preferences_encrypted: Vec::new(),
            user_keystore_encrypted: Vec::new(),
        };

        let user_dao = user::Dao::new(&env::testing::DB_THREAD_POOL);

        let user_id = user_dao
            .create_user(
                &new_user.email,
                "",
                &new_user.auth_string_salt,
                new_user.auth_string_memory_cost_kib,
                new_user.auth_string_parallelism_factor,
                new_user.auth_string_iters,
                &new_user.password_encryption_salt,
                new_user.password_encryption_memory_cost_kib,
                new_user.password_encryption_parallelism_factor,
                new_user.password_encryption_iters,
                &new_user.recovery_key_salt,
                new_user.recovery_key_memory_cost_kib,
                new_user.recovery_key_parallelism_factor,
                new_user.recovery_key_iters,
                &new_user.encryption_key_encrypted_with_password,
                &new_user.encryption_key_encrypted_with_recovery_key,
                public_key_id,
                &new_user.public_key,
                &new_user.preferences_encrypted,
                &new_user.user_keystore_encrypted,
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
