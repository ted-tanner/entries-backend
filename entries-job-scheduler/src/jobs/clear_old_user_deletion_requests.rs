use entries_common::db::user::Dao as UserDao;
use entries_common::db::DbAsyncPool;

use async_trait::async_trait;

use crate::jobs::{Job, JobError};

pub struct ClearOldUserDeletionRequestsJob {
    db_async_pool: DbAsyncPool,
    is_running: bool,
}

impl ClearOldUserDeletionRequestsJob {
    pub fn new(db_async_pool: DbAsyncPool) -> Self {
        Self {
            db_async_pool,
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

        let dao = UserDao::new(&self.db_async_pool);
        dao.delete_old_user_deletion_requests().await?;

        self.is_running = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use entries_common::messages::NewUser;
    use entries_common::models::container::NewContainer;
    use entries_common::models::container_access_key::NewContainerAccessKey;
    use entries_common::models::user_deletion_request::NewUserDeletionRequest;
    use entries_common::models::user_deletion_request_container_key::NewUserDeletionRequestContainerKey;
    use entries_common::schema::{
        container_access_keys, containers, user_deletion_request_container_keys,
    };
    use entries_common::threadrand::SecureRng;
    use entries_common::{db::user, schema::user_deletion_requests};

    use diesel::QueryDsl;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    use crate::env;

    #[tokio::test]
    async fn test_execute() {
        let user1_number = SecureRng::next_u128();

        let public_key_id = Uuid::now_v7();
        let new_user1 = NewUser {
            email: format!("test_user{}@test.com", &user1_number),

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

        let user_dao = user::Dao::new(&env::testing::DB_ASYNC_POOL);

        let user1_id = user_dao
            .create_user(
                &new_user1.email,
                "",
                &new_user1.auth_string_hash_salt,
                new_user1.auth_string_hash_mem_cost_kib,
                new_user1.auth_string_hash_threads,
                new_user1.auth_string_hash_iterations,
                &new_user1.password_encryption_key_salt,
                new_user1.password_encryption_key_mem_cost_kib,
                new_user1.password_encryption_key_threads,
                new_user1.password_encryption_key_iterations,
                &new_user1.recovery_key_hash_salt_for_encryption,
                &new_user1.recovery_key_hash_salt_for_recovery_auth,
                new_user1.recovery_key_hash_mem_cost_kib,
                new_user1.recovery_key_hash_threads,
                new_user1.recovery_key_hash_iterations,
                "",
                &new_user1.encryption_key_encrypted_with_password,
                &new_user1.encryption_key_encrypted_with_recovery_key,
                public_key_id,
                &new_user1.public_key,
                &new_user1.preferences_encrypted,
                new_user1.preferences_version_nonce,
                &new_user1.user_keystore_encrypted,
                new_user1.user_keystore_version_nonce,
            )
            .await
            .unwrap();
        user_dao.verify_user_creation(user1_id).await.unwrap();

        let user2_number = SecureRng::next_u128();

        let public_key_id = Uuid::now_v7();
        let new_user2 = NewUser {
            email: format!("test_user{}@test.com", &user2_number),

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

        let user2_id = user_dao
            .create_user(
                &new_user2.email,
                "",
                &new_user2.auth_string_hash_salt,
                new_user2.auth_string_hash_mem_cost_kib,
                new_user2.auth_string_hash_threads,
                new_user2.auth_string_hash_iterations,
                &new_user2.password_encryption_key_salt,
                new_user2.password_encryption_key_mem_cost_kib,
                new_user2.password_encryption_key_threads,
                new_user2.password_encryption_key_iterations,
                &new_user2.recovery_key_hash_salt_for_encryption,
                &new_user2.recovery_key_hash_salt_for_recovery_auth,
                new_user2.recovery_key_hash_mem_cost_kib,
                new_user2.recovery_key_hash_threads,
                new_user2.recovery_key_hash_iterations,
                "",
                &new_user2.encryption_key_encrypted_with_password,
                &new_user2.encryption_key_encrypted_with_recovery_key,
                public_key_id,
                &new_user2.public_key,
                &new_user2.preferences_encrypted,
                new_user2.preferences_version_nonce,
                &new_user2.user_keystore_encrypted,
                new_user2.user_keystore_version_nonce,
            )
            .await
            .unwrap();
        user_dao.verify_user_creation(user2_id).await.unwrap();

        let new_container = NewContainer {
            id: Uuid::now_v7(),
            encrypted_blob: &[0; 4],
            version_nonce: SecureRng::next_i64(),
            modified_timestamp: SystemTime::now(),
        };

        diesel_async::RunQueryDsl::execute(
            diesel::insert_into(containers::table).values(&new_container),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let new_container_access_key1 = NewContainerAccessKey {
            key_id: Uuid::now_v7(),
            container_id: new_container.id,
            public_key: &[0; 4],
            read_only: false,
        };

        diesel_async::RunQueryDsl::execute(
            diesel::insert_into(container_access_keys::table).values(&new_container_access_key1),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let new_container_access_key2 = NewContainerAccessKey {
            key_id: Uuid::now_v7(),
            container_id: new_container.id,
            public_key: &[0; 4],
            read_only: false,
        };

        diesel_async::RunQueryDsl::execute(
            diesel::insert_into(container_access_keys::table).values(&new_container_access_key2),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let new_deletion_req_exp = NewUserDeletionRequest {
            user_id: user1_id,
            ready_for_deletion_time: SystemTime::now() + Duration::from_secs(10),
        };

        diesel_async::RunQueryDsl::execute(
            diesel::insert_into(user_deletion_requests::table).values(&new_deletion_req_exp),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let new_deletion_req_key_exp = NewUserDeletionRequestContainerKey {
            key_id: new_container_access_key1.key_id,
            user_id: user1_id,
            delete_me_time: SystemTime::now() - Duration::from_nanos(1),
        };

        diesel_async::RunQueryDsl::execute(
            diesel::insert_into(user_deletion_request_container_keys::table)
                .values(&new_deletion_req_key_exp),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let new_deletion_req_not_exp = NewUserDeletionRequest {
            user_id: user2_id,
            ready_for_deletion_time: SystemTime::now() + Duration::from_secs(10),
        };

        diesel_async::RunQueryDsl::execute(
            diesel::insert_into(user_deletion_requests::table).values(&new_deletion_req_not_exp),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let new_deletion_req_key_not_exp = NewUserDeletionRequestContainerKey {
            key_id: new_container_access_key2.key_id,
            user_id: user2_id,
            delete_me_time: SystemTime::now() + Duration::from_secs(10),
        };

        diesel_async::RunQueryDsl::execute(
            diesel::insert_into(user_deletion_request_container_keys::table)
                .values(&new_deletion_req_key_not_exp),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let mut job = ClearOldUserDeletionRequestsJob::new(env::testing::DB_ASYNC_POOL.clone());

        let count = diesel_async::RunQueryDsl::execute(
            user_deletion_requests::table.find(new_deletion_req_exp.user_id),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(count, 1);

        let count = diesel_async::RunQueryDsl::execute(
            user_deletion_request_container_keys::table.find(new_deletion_req_key_exp.key_id),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(count, 1);

        let count = diesel_async::RunQueryDsl::execute(
            user_deletion_requests::table.find(new_deletion_req_not_exp.user_id),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(count, 1);

        let count = diesel_async::RunQueryDsl::execute(
            user_deletion_request_container_keys::table.find(new_deletion_req_key_not_exp.key_id),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(count, 1);

        job.execute().await.unwrap();

        let count = diesel_async::RunQueryDsl::execute(
            user_deletion_requests::table.find(new_deletion_req_exp.user_id),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(count, 0);

        let count = diesel_async::RunQueryDsl::execute(
            user_deletion_request_container_keys::table.find(new_deletion_req_key_exp.key_id),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(count, 0);

        let count = diesel_async::RunQueryDsl::execute(
            user_deletion_requests::table.find(new_deletion_req_not_exp.user_id),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(count, 1);

        let count = diesel_async::RunQueryDsl::execute(
            user_deletion_request_container_keys::table.find(new_deletion_req_key_not_exp.key_id),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(count, 1);
    }
}
