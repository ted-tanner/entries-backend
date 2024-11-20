use entries_common::db::user::Dao as UserDao;
use entries_common::db::DbThreadPool;

use async_trait::async_trait;
use futures::future;

use crate::jobs::{Job, JobError};

pub struct DeleteUsersJob {
    db_thread_pool: DbThreadPool,
    is_running: bool,
}

impl DeleteUsersJob {
    pub fn new(db_thread_pool: DbThreadPool) -> Self {
        Self {
            db_thread_pool,
            is_running: false,
        }
    }
}

#[async_trait]
impl Job for DeleteUsersJob {
    fn name(&self) -> &'static str {
        "Delete Users"
    }

    fn is_ready(&self) -> bool {
        !self.is_running
    }

    async fn execute(&mut self) -> Result<(), JobError> {
        self.is_running = true;

        let dao = UserDao::new(&self.db_thread_pool);

        let users_ready_for_deletion =
            tokio::task::spawn_blocking(move || dao.get_all_users_ready_for_deletion()).await??;

        let mut delete_user_futures = Vec::new();

        for user in users_ready_for_deletion {
            let dao = UserDao::new(&self.db_thread_pool);

            delete_user_futures.push(tokio::task::spawn_blocking(move || {
                let result = dao.delete_user(&user);

                if let Err(e) = &result {
                    log::error!("User deletion failed for user {}: {}", &user.user_id, e);
                }

                result
            }));
        }

        let results = future::join_all(delete_user_futures).await;

        for result in results.into_iter() {
            if let Err(e) = result? {
                log::error!("Failed to delete user: {}", e);
                return Err(e.into());
            }
        }

        self.is_running = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use entries_common::db::budget;
    use entries_common::messages::NewUser;
    use entries_common::models::budget::NewBudget;
    use entries_common::models::budget_access_key::NewBudgetAccessKey;
    use entries_common::models::user_deletion_request::NewUserDeletionRequest;
    use entries_common::models::user_deletion_request_budget_key::NewUserDeletionRequestBudgetKey;
    use entries_common::schema::{
        budget_access_keys, budgets, categories, entries, user_deletion_request_budget_keys,
        user_keystores, user_preferences,
    };
    use entries_common::{db::user, schema::user_deletion_requests};

    use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use rand::Rng;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    use crate::env;

    #[tokio::test]
    async fn test_execute() {
        let user1_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let public_key_id = Uuid::new_v4();
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

            public_key_id: public_key_id.into(),
            public_key: Vec::new(),

            preferences_encrypted: Vec::new(),
            preferences_version_nonce: rand::thread_rng().gen(),
            user_keystore_encrypted: Vec::new(),
            user_keystore_version_nonce: rand::thread_rng().gen(),
        };

        let user_dao = user::Dao::new(&env::testing::DB_THREAD_POOL);

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
                public_key_id,
                &new_user1.public_key,
                &new_user1.preferences_encrypted,
                new_user1.preferences_version_nonce,
                &new_user1.user_keystore_encrypted,
                new_user1.user_keystore_version_nonce,
                &Vec::new(),
            )
            .unwrap();
        user_dao.verify_user_creation(user1_id).unwrap();

        let user2_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let public_key_id = Uuid::new_v4();
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

            public_key_id: public_key_id.into(),
            public_key: Vec::new(),

            preferences_encrypted: Vec::new(),
            preferences_version_nonce: rand::thread_rng().gen(),
            user_keystore_encrypted: Vec::new(),
            user_keystore_version_nonce: rand::thread_rng().gen(),
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
                public_key_id,
                &new_user2.public_key,
                &new_user2.preferences_encrypted,
                new_user2.preferences_version_nonce,
                &new_user2.user_keystore_encrypted,
                new_user2.user_keystore_version_nonce,
                &Vec::new(),
            )
            .unwrap();
        user_dao.verify_user_creation(user2_id).unwrap();

        let new_budget1 = NewBudget {
            id: Uuid::new_v4(),
            encrypted_blob: &[0; 4],
            version_nonce: rand::thread_rng().gen(),
            modified_timestamp: SystemTime::now(),
        };

        diesel::insert_into(budgets::table)
            .values(&new_budget1)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_budget2 = NewBudget {
            id: Uuid::new_v4(),
            encrypted_blob: &[0; 4],
            version_nonce: rand::thread_rng().gen(),
            modified_timestamp: SystemTime::now(),
        };

        diesel::insert_into(budgets::table)
            .values(&new_budget2)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let budget_dao = budget::Dao::new(&env::testing::DB_THREAD_POOL);

        let out = budget_dao
            .create_entry_and_category(
                &[0],
                rand::thread_rng().gen(),
                &[0],
                rand::thread_rng().gen(),
                new_budget1.id,
            )
            .unwrap();

        let budget1_entry_id = Uuid::try_from(out.entry_id).unwrap();
        let budget1_category_id = Uuid::try_from(out.category_id).unwrap();

        let out = budget_dao
            .create_entry_and_category(
                &[0],
                rand::thread_rng().gen(),
                &[0],
                rand::thread_rng().gen(),
                new_budget2.id,
            )
            .unwrap();

        let budget2_entry_id = Uuid::try_from(out.entry_id).unwrap();
        let budget2_category_id = Uuid::try_from(out.category_id).unwrap();

        let new_budget1_access_key1 = NewBudgetAccessKey {
            key_id: Uuid::new_v4(),
            budget_id: new_budget1.id,
            public_key: &[0; 4],
            read_only: false,
        };

        diesel::insert_into(budget_access_keys::table)
            .values(&new_budget1_access_key1)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_budget1_access_key2 = NewBudgetAccessKey {
            key_id: Uuid::new_v4(),
            budget_id: new_budget1.id,
            public_key: &[0; 4],
            read_only: false,
        };

        diesel::insert_into(budget_access_keys::table)
            .values(&new_budget1_access_key2)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_budget2_access_key1 = NewBudgetAccessKey {
            key_id: Uuid::new_v4(),
            budget_id: new_budget2.id,
            public_key: &[0; 4],
            read_only: false,
        };

        diesel::insert_into(budget_access_keys::table)
            .values(&new_budget2_access_key1)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_deletion_req_ready = NewUserDeletionRequest {
            user_id: user1_id,
            ready_for_deletion_time: SystemTime::now() - Duration::from_secs(10),
        };

        diesel::insert_into(user_deletion_requests::table)
            .values(&new_deletion_req_ready)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_deletion_req_key_ready_budget2 = NewUserDeletionRequestBudgetKey {
            key_id: new_budget2_access_key1.key_id,
            user_id: user1_id,
            delete_me_time: SystemTime::now() + Duration::from_secs(10),
        };

        diesel::insert_into(user_deletion_request_budget_keys::table)
            .values(&new_deletion_req_key_ready_budget2)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_deletion_req_key_ready = NewUserDeletionRequestBudgetKey {
            key_id: new_budget1_access_key1.key_id,
            user_id: user1_id,
            delete_me_time: SystemTime::now() + Duration::from_secs(10),
        };

        diesel::insert_into(user_deletion_request_budget_keys::table)
            .values(&new_deletion_req_key_ready)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_deletion_req_not_ready = NewUserDeletionRequest {
            user_id: user2_id,
            ready_for_deletion_time: SystemTime::now() + Duration::from_secs(10),
        };

        diesel::insert_into(user_deletion_requests::table)
            .values(&new_deletion_req_not_ready)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_deletion_req_key_not_ready = NewUserDeletionRequestBudgetKey {
            key_id: new_budget1_access_key2.key_id,
            user_id: user2_id,
            delete_me_time: SystemTime::now() + Duration::from_secs(10),
        };

        diesel::insert_into(user_deletion_request_budget_keys::table)
            .values(&new_deletion_req_key_not_ready)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let mut job = DeleteUsersJob::new(env::testing::DB_THREAD_POOL.clone());

        assert_eq!(
            user_deletion_requests::table
                .find(new_deletion_req_ready.user_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            user_deletion_request_budget_keys::table
                .find(new_deletion_req_key_ready.key_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            budget_access_keys::table
                .find((
                    new_budget1_access_key1.key_id,
                    new_budget1_access_key1.budget_id
                ))
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            user_deletion_request_budget_keys::table
                .find(new_deletion_req_key_ready_budget2.key_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            budget_access_keys::table
                .find((
                    new_budget2_access_key1.key_id,
                    new_budget2_access_key1.budget_id
                ))
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            user_deletion_requests::table
                .find(new_deletion_req_not_ready.user_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            user_deletion_request_budget_keys::table
                .find(new_deletion_req_key_not_ready.key_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            budget_access_keys::table
                .find((
                    new_budget1_access_key2.key_id,
                    new_budget1_access_key2.budget_id
                ))
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            budgets::table
                .find(new_budget1.id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            budgets::table
                .find(new_budget2.id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            entries::table
                .find(budget1_entry_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            categories::table
                .find(budget1_category_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            entries::table
                .find(budget2_entry_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            categories::table
                .find(budget2_category_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            user_preferences::table
                .find(user1_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            user_keystores::table
                .find(user1_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            user_preferences::table
                .find(user2_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            user_keystores::table
                .find(user2_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        job.execute().await.unwrap();

        assert_eq!(
            user_deletion_requests::table
                .find(new_deletion_req_ready.user_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_deletion_request_budget_keys::table
                .find(new_deletion_req_key_ready.key_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            budget_access_keys::table
                .find((
                    new_budget1_access_key1.key_id,
                    new_budget1_access_key1.budget_id
                ))
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_deletion_request_budget_keys::table
                .find(new_deletion_req_key_ready_budget2.key_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            budget_access_keys::table
                .find((
                    new_budget2_access_key1.key_id,
                    new_budget2_access_key1.budget_id
                ))
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_deletion_requests::table
                .find(new_deletion_req_not_ready.user_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            user_deletion_request_budget_keys::table
                .find(new_deletion_req_key_not_ready.key_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            budget_access_keys::table
                .find((
                    new_budget1_access_key2.key_id,
                    new_budget1_access_key2.budget_id
                ))
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            budgets::table
                .find(new_budget1.id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            budgets::table
                .find(new_budget2.id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            entries::table
                .find(budget1_entry_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            categories::table
                .find(budget1_category_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            entries::table
                .find(budget1_entry_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            categories::table
                .find(budget1_category_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            entries::table
                .find(budget2_entry_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            categories::table
                .find(budget2_category_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_preferences::table
                .find(user1_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_keystores::table
                .find(user1_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_preferences::table
                .find(user2_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            user_keystores::table
                .find(user2_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        diesel::update(user_deletion_requests::table.find(new_deletion_req_not_ready.user_id))
            .set(
                user_deletion_requests::ready_for_deletion_time
                    .eq(SystemTime::now() - Duration::from_secs(10)),
            )
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        job.execute().await.unwrap();

        assert_eq!(
            user_deletion_requests::table
                .find(new_deletion_req_ready.user_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_deletion_request_budget_keys::table
                .find(new_deletion_req_key_ready.key_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            budget_access_keys::table
                .find((
                    new_budget1_access_key1.key_id,
                    new_budget1_access_key1.budget_id
                ))
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_deletion_request_budget_keys::table
                .find(new_deletion_req_key_ready_budget2.key_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            budget_access_keys::table
                .find((
                    new_budget2_access_key1.key_id,
                    new_budget2_access_key1.budget_id
                ))
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_deletion_requests::table
                .find(new_deletion_req_not_ready.user_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_deletion_request_budget_keys::table
                .find(new_deletion_req_key_not_ready.key_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            budget_access_keys::table
                .find((
                    new_budget1_access_key2.key_id,
                    new_budget1_access_key2.budget_id
                ))
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            budgets::table
                .find(new_budget1.id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            budgets::table
                .find(new_budget2.id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            entries::table
                .find(budget1_entry_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            categories::table
                .find(budget1_category_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            entries::table
                .find(budget1_entry_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            categories::table
                .find(budget1_category_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            entries::table
                .find(budget2_entry_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            categories::table
                .find(budget2_category_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_preferences::table
                .find(user1_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_keystores::table
                .find(user1_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_preferences::table
                .find(user2_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            user_keystores::table
                .find(user2_id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );
    }
}
