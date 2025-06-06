use entries_common::db::user::Dao as UserDao;
use entries_common::db::DbThreadPool;

use async_trait::async_trait;
use std::time::Duration;

use crate::jobs::{Job, JobError};

pub struct ClearUnverifiedUsersJob {
    pub max_unverified_user_age: Duration,

    db_thread_pool: DbThreadPool,
    is_running: bool,
}

impl ClearUnverifiedUsersJob {
    pub fn new(max_unverified_user_age: Duration, db_thread_pool: DbThreadPool) -> Self {
        Self {
            max_unverified_user_age,
            db_thread_pool,
            is_running: false,
        }
    }
}

#[async_trait]
impl Job for ClearUnverifiedUsersJob {
    fn name(&self) -> &'static str {
        "Clear Unverified Users"
    }

    fn is_ready(&self) -> bool {
        !self.is_running
    }

    async fn execute(&mut self) -> Result<(), JobError> {
        self.is_running = true;

        let max_unverified_user_age = self.max_unverified_user_age;
        let dao = UserDao::new(&self.db_thread_pool);

        tokio::task::spawn_blocking(move || dao.clear_unverified_users(max_unverified_user_age))
            .await??;

        self.is_running = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use entries_common::db::user;
    use entries_common::messages::NewUser;
    use entries_common::schema::users;
    use entries_common::threadrand::SecureRng;

    use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    use crate::env;

    #[tokio::test]
    async fn test_execute() {
        let user_no_exp_number = SecureRng::next_u128();

        let public_key_id = Uuid::now_v7();
        let new_user_no_exp = NewUser {
            email: format!("test_user{}@test.com", &user_no_exp_number),

            auth_string: Vec::new(),

            auth_string_hash_salt: Vec::new(),
            auth_string_hash_mem_cost_kib: 1024,
            auth_string_hash_threads: 1,
            auth_string_hash_iterations: 2,

            password_encryption_key_salt: Vec::new(),
            password_encryption_key_mem_cost_kib: 1024,
            password_encryption_key_threads: 1,
            password_encryption_key_iterations: 2,

            recovery_key_hash_salt_for_encryption: Vec::new(),
            recovery_key_hash_salt_for_recovery_auth: Vec::new(),
            recovery_key_hash_mem_cost_kib: 1024,
            recovery_key_hash_threads: 1,
            recovery_key_hash_iterations: 2,

            recovery_key_auth_hash: Vec::new(),

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

        let user_no_exp_id = user_dao
            .create_user(
                &new_user_no_exp.email,
                "",
                &new_user_no_exp.auth_string_hash_salt,
                new_user_no_exp.auth_string_hash_mem_cost_kib,
                new_user_no_exp.auth_string_hash_threads,
                new_user_no_exp.auth_string_hash_iterations,
                &new_user_no_exp.password_encryption_key_salt,
                new_user_no_exp.password_encryption_key_mem_cost_kib,
                new_user_no_exp.password_encryption_key_threads,
                new_user_no_exp.password_encryption_key_iterations,
                &new_user_no_exp.recovery_key_hash_salt_for_encryption,
                &new_user_no_exp.recovery_key_hash_salt_for_recovery_auth,
                new_user_no_exp.recovery_key_hash_mem_cost_kib,
                new_user_no_exp.recovery_key_hash_threads,
                new_user_no_exp.recovery_key_hash_iterations,
                "",
                &new_user_no_exp.encryption_key_encrypted_with_password,
                &new_user_no_exp.encryption_key_encrypted_with_recovery_key,
                public_key_id,
                &new_user_no_exp.public_key,
                &new_user_no_exp.preferences_encrypted,
                new_user_no_exp.preferences_version_nonce,
                &new_user_no_exp.user_keystore_encrypted,
                new_user_no_exp.user_keystore_version_nonce,
            )
            .unwrap();

        let user_verified_number = SecureRng::next_u128();

        let public_key_id = Uuid::now_v7();
        let new_user_verified = NewUser {
            email: format!("test_user{}@test.com", &user_verified_number),

            auth_string: Vec::new(),

            auth_string_hash_salt: Vec::new(),
            auth_string_hash_mem_cost_kib: 1024,
            auth_string_hash_threads: 1,
            auth_string_hash_iterations: 2,

            password_encryption_key_salt: Vec::new(),
            password_encryption_key_mem_cost_kib: 1024,
            password_encryption_key_threads: 1,
            password_encryption_key_iterations: 2,

            recovery_key_hash_salt_for_encryption: Vec::new(),
            recovery_key_hash_salt_for_recovery_auth: Vec::new(),
            recovery_key_hash_mem_cost_kib: 1024,
            recovery_key_hash_threads: 1,
            recovery_key_hash_iterations: 2,

            recovery_key_auth_hash: Vec::new(),

            encryption_key_encrypted_with_password: Vec::new(),
            encryption_key_encrypted_with_recovery_key: Vec::new(),

            public_key_id: public_key_id.into(),
            public_key: Vec::new(),

            preferences_encrypted: Vec::new(),
            preferences_version_nonce: SecureRng::next_i64(),
            user_keystore_encrypted: Vec::new(),
            user_keystore_version_nonce: SecureRng::next_i64(),
        };

        let user_verified_id = user_dao
            .create_user(
                &new_user_verified.email,
                "",
                &new_user_verified.auth_string_hash_salt,
                new_user_verified.auth_string_hash_mem_cost_kib,
                new_user_verified.auth_string_hash_threads,
                new_user_verified.auth_string_hash_iterations,
                &new_user_verified.password_encryption_key_salt,
                new_user_verified.password_encryption_key_mem_cost_kib,
                new_user_verified.password_encryption_key_threads,
                new_user_verified.password_encryption_key_iterations,
                &new_user_verified.recovery_key_hash_salt_for_encryption,
                &new_user_verified.recovery_key_hash_salt_for_recovery_auth,
                new_user_verified.recovery_key_hash_mem_cost_kib,
                new_user_verified.recovery_key_hash_threads,
                new_user_verified.recovery_key_hash_iterations,
                "",
                &new_user_verified.encryption_key_encrypted_with_password,
                &new_user_verified.encryption_key_encrypted_with_recovery_key,
                public_key_id,
                &new_user_verified.public_key,
                &new_user_verified.preferences_encrypted,
                new_user_verified.preferences_version_nonce,
                &new_user_verified.user_keystore_encrypted,
                new_user_verified.user_keystore_version_nonce,
            )
            .unwrap();
        user_dao.verify_user_creation(user_verified_id).unwrap();

        diesel::update(users::table.find(user_verified_id))
            .set(users::created_timestamp.eq(SystemTime::now() - Duration::from_secs(864_000)))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let user_exp_number = SecureRng::next_u128();

        let public_key_id = Uuid::now_v7();
        let new_user_exp = NewUser {
            email: format!("test_user{}@test.com", &user_exp_number),

            auth_string: Vec::new(),

            auth_string_hash_salt: Vec::new(),
            auth_string_hash_mem_cost_kib: 1024,
            auth_string_hash_threads: 1,
            auth_string_hash_iterations: 2,

            password_encryption_key_salt: Vec::new(),
            password_encryption_key_mem_cost_kib: 1024,
            password_encryption_key_threads: 1,
            password_encryption_key_iterations: 2,

            recovery_key_hash_salt_for_encryption: Vec::new(),
            recovery_key_hash_salt_for_recovery_auth: Vec::new(),
            recovery_key_hash_mem_cost_kib: 1024,
            recovery_key_hash_threads: 1,
            recovery_key_hash_iterations: 2,

            recovery_key_auth_hash: Vec::new(),

            encryption_key_encrypted_with_password: Vec::new(),
            encryption_key_encrypted_with_recovery_key: Vec::new(),

            public_key_id: public_key_id.into(),
            public_key: Vec::new(),

            preferences_encrypted: Vec::new(),
            preferences_version_nonce: SecureRng::next_i64(),
            user_keystore_encrypted: Vec::new(),
            user_keystore_version_nonce: SecureRng::next_i64(),
        };

        let user_exp_id = user_dao
            .create_user(
                &new_user_exp.email,
                "",
                &new_user_exp.auth_string_hash_salt,
                new_user_exp.auth_string_hash_mem_cost_kib,
                new_user_exp.auth_string_hash_threads,
                new_user_exp.auth_string_hash_iterations,
                &new_user_exp.password_encryption_key_salt,
                new_user_exp.password_encryption_key_mem_cost_kib,
                new_user_exp.password_encryption_key_threads,
                new_user_exp.password_encryption_key_iterations,
                &new_user_exp.recovery_key_hash_salt_for_encryption,
                &new_user_exp.recovery_key_hash_salt_for_recovery_auth,
                new_user_exp.recovery_key_hash_mem_cost_kib,
                new_user_exp.recovery_key_hash_threads,
                new_user_exp.recovery_key_hash_iterations,
                "",
                &new_user_exp.encryption_key_encrypted_with_password,
                &new_user_exp.encryption_key_encrypted_with_recovery_key,
                public_key_id,
                &new_user_exp.public_key,
                &new_user_exp.preferences_encrypted,
                new_user_exp.preferences_version_nonce,
                &new_user_exp.user_keystore_encrypted,
                new_user_exp.user_keystore_version_nonce,
            )
            .unwrap();

        diesel::update(users::table.find(user_exp_id))
            .set(users::created_timestamp.eq(SystemTime::now() - Duration::from_secs(864_000)))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let mut job = ClearUnverifiedUsersJob::new(
            Duration::from_secs(86400),
            env::testing::DB_THREAD_POOL.clone(),
        );

        assert_eq!(
            users::table
                .find(user_no_exp_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            users::table
                .find(user_verified_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            users::table
                .find(user_exp_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        job.execute().await.unwrap();

        assert_eq!(
            users::table
                .find(user_no_exp_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            users::table
                .find(user_verified_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            users::table
                .find(user_exp_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );
    }
}
