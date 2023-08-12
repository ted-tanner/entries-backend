use entries_utils::db::user::Dao as UserDao;
use entries_utils::db::DbThreadPool;

use async_trait::async_trait;

use crate::jobs::{Job, JobError};

pub struct ClearOldUserDeletionRequestsJob {
    db_thread_pool: DbThreadPool,
    is_running: bool,
}

impl ClearOldUserDeletionRequestsJob {
    pub fn new(db_thread_pool: DbThreadPool) -> Self {
        Self {
            db_thread_pool,
            is_running: false,
        }
    }
}

#[async_trait]
impl Job for ClearOldUserDeletionRequestsJob {
    fn name(&self) -> &'static str {
        "Clear Old User Deletion Requests"
    }

    fn is_ready(&self) -> bool {
        !self.is_running
    }

    async fn execute(&mut self) -> Result<(), JobError> {
        self.is_running = true;

        let mut dao = UserDao::new(&self.db_thread_pool);
        tokio::task::spawn_blocking(move || dao.delete_old_user_deletion_requests()).await??;

        self.is_running = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use entries_utils::messages::NewUser;
    use entries_utils::models::budget::NewBudget;
    use entries_utils::models::budget_access_key::NewBudgetAccessKey;
    use entries_utils::models::user_deletion_request::NewUserDeletionRequest;
    use entries_utils::models::user_deletion_request_budget_key::NewUserDeletionRequestBudgetKey;
    use entries_utils::schema::{budget_access_keys, budgets, user_deletion_request_budget_keys};
    use entries_utils::{db::user, schema::user_deletion_requests};

    use diesel::{QueryDsl, RunQueryDsl};
    use rand::Rng;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    use crate::env;

    #[tokio::test]
    async fn test_execute() {
        let user1_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user1 = NewUser {
            email: format!("test_user{}@test.com", &user1_number),

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
        };

        let mut user_dao = user::Dao::new(&env::testing::DB_THREAD_POOL);

        let user1_id = user_dao
            .create_user(
                &new_user1.email,
                "",
                &new_user1.auth_string_salt,
                new_user1.auth_string_memory_cost_kib,
                new_user1.auth_string_parallelism_factor,
                new_user1.auth_string_iters,
                &new_user1.password_encryption_salt,
                new_user1.password_encryption_memory_cost_kib,
                new_user1.password_encryption_parallelism_factor,
                new_user1.password_encryption_iters,
                &new_user1.recovery_key_salt,
                new_user1.recovery_key_memory_cost_kib,
                new_user1.recovery_key_parallelism_factor,
                new_user1.recovery_key_iters,
                &new_user1.encryption_key_encrypted_with_password,
                &new_user1.encryption_key_encrypted_with_recovery_key,
                &new_user1.public_key,
                &new_user1.preferences_encrypted,
                &new_user1.user_keystore_encrypted,
                &Vec::new(),
            )
            .unwrap();
        user_dao.verify_user_creation(user1_id).unwrap();

        let user2_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user2 = NewUser {
            email: format!("test_user{}@test.com", &user2_number),

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
        };

        let user2_id = user_dao
            .create_user(
                &new_user2.email,
                "",
                &new_user2.auth_string_salt,
                new_user2.auth_string_memory_cost_kib,
                new_user2.auth_string_parallelism_factor,
                new_user2.auth_string_iters,
                &new_user2.password_encryption_salt,
                new_user2.password_encryption_memory_cost_kib,
                new_user2.password_encryption_parallelism_factor,
                new_user2.password_encryption_iters,
                &new_user2.recovery_key_salt,
                new_user2.recovery_key_memory_cost_kib,
                new_user2.recovery_key_parallelism_factor,
                new_user2.recovery_key_iters,
                &new_user2.encryption_key_encrypted_with_password,
                &new_user2.encryption_key_encrypted_with_recovery_key,
                &new_user2.public_key,
                &new_user2.preferences_encrypted,
                &new_user2.user_keystore_encrypted,
                &Vec::new(),
            )
            .unwrap();
        user_dao.verify_user_creation(user2_id).unwrap();

        let new_budget = NewBudget {
            id: Uuid::new_v4(),
            encrypted_blob: &[0; 4],
            encrypted_blob_sha1_hash: &[0; 4],
            modified_timestamp: SystemTime::now(),
        };

        diesel::insert_into(budgets::table)
            .values(&new_budget)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_budget_access_key1 = NewBudgetAccessKey {
            key_id: Uuid::new_v4(),
            budget_id: new_budget.id,
            public_key: &[0; 4],
            read_only: false,
        };

        diesel::insert_into(budget_access_keys::table)
            .values(&new_budget_access_key1)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_budget_access_key2 = NewBudgetAccessKey {
            key_id: Uuid::new_v4(),
            budget_id: new_budget.id,
            public_key: &[0; 4],
            read_only: false,
        };

        diesel::insert_into(budget_access_keys::table)
            .values(&new_budget_access_key2)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_deletion_req_exp = NewUserDeletionRequest {
            id: Uuid::new_v4(),
            user_id: user1_id,
            ready_for_deletion_time: SystemTime::now() + Duration::from_secs(10),
        };

        diesel::insert_into(user_deletion_requests::table)
            .values(&new_deletion_req_exp)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_deletion_req_key_exp = NewUserDeletionRequestBudgetKey {
            key_id: new_budget_access_key1.key_id,
            user_id: user1_id,
            delete_me_time: SystemTime::now() - Duration::from_nanos(1),
        };

        diesel::insert_into(user_deletion_request_budget_keys::table)
            .values(&new_deletion_req_key_exp)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_deletion_req_not_exp = NewUserDeletionRequest {
            id: Uuid::new_v4(),
            user_id: user2_id,
            ready_for_deletion_time: SystemTime::now() + Duration::from_secs(10),
        };

        diesel::insert_into(user_deletion_requests::table)
            .values(&new_deletion_req_not_exp)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_deletion_req_key_not_exp = NewUserDeletionRequestBudgetKey {
            key_id: new_budget_access_key2.key_id,
            user_id: user2_id,
            delete_me_time: SystemTime::now() + Duration::from_secs(10),
        };

        diesel::insert_into(user_deletion_request_budget_keys::table)
            .values(&new_deletion_req_key_not_exp)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let mut job = ClearOldUserDeletionRequestsJob::new(env::testing::DB_THREAD_POOL.clone());

        assert_eq!(
            user_deletion_requests::table
                .find(new_deletion_req_exp.id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            user_deletion_request_budget_keys::table
                .find(new_deletion_req_key_exp.key_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            user_deletion_requests::table
                .find(new_deletion_req_not_exp.id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            user_deletion_request_budget_keys::table
                .find(new_deletion_req_key_not_exp.key_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        job.execute().await.unwrap();

        assert_eq!(
            user_deletion_requests::table
                .find(new_deletion_req_exp.id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_deletion_request_budget_keys::table
                .find(new_deletion_req_key_exp.key_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_deletion_requests::table
                .find(new_deletion_req_not_exp.id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            user_deletion_request_budget_keys::table
                .find(new_deletion_req_key_not_exp.key_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );
    }
}
