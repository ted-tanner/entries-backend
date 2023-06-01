use entries_utils::db::user::Dao as UserDao;
use entries_utils::db::DbThreadPool;

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
        let mut dao = UserDao::new(&self.db_thread_pool);

        tokio::task::spawn_blocking(move || dao.clear_unverified_users(max_unverified_user_age))
            .await??;

        self.is_running = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use entries_utils::db::user;
    use entries_utils::request_io::InputUser;
    use entries_utils::schema::users;

    use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use rand::Rng;
    use std::time::{Duration, SystemTime};

    use crate::env;

    #[tokio::test]
    async fn test_execute() {
        let user_no_exp_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user_no_exp = InputUser {
            email: format!("test_user{}@test.com", &user_no_exp_number),

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

        let user_no_exp_id = user_dao
            .create_user(&new_user_no_exp, "Test", &Vec::new())
            .unwrap();

        let user_verified_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user_verified = InputUser {
            email: format!("test_user{}@test.com", &user_verified_number),

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

        let user_verified_id = user_dao
            .create_user(&new_user_verified, "Test", &Vec::new())
            .unwrap();
        user_dao.verify_user_creation(user_verified_id).unwrap();

        diesel::update(users::table.find(user_verified_id))
            .set(users::created_timestamp.eq(SystemTime::now() - Duration::from_secs(864_000)))
            .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let user_exp_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user_exp = InputUser {
            email: format!("test_user{}@test.com", &user_exp_number),

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

        let user_exp_id = user_dao
            .create_user(&new_user_exp, "Test", &Vec::new())
            .unwrap();

        diesel::update(users::table.find(user_exp_id))
            .set(users::created_timestamp.eq(SystemTime::now() - Duration::from_secs(864_000)))
            .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let mut job = ClearUnverifiedUsersJob::new(
            Duration::from_secs(86400),
            env::db::DB_THREAD_POOL.clone(),
        );

        assert_eq!(
            users::table
                .find(user_no_exp_id)
                .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            users::table
                .find(user_verified_id)
                .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            users::table
                .find(user_exp_id)
                .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        job.execute().await.unwrap();

        assert_eq!(
            users::table
                .find(user_no_exp_id)
                .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            users::table
                .find(user_verified_id)
                .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            users::table
                .find(user_exp_id)
                .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );
    }
}
