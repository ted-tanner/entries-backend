use entries_common::db::container::Dao as ContainerDao;
use entries_common::db::DbThreadPool;

use async_trait::async_trait;

use crate::jobs::{Job, JobError};

pub struct ClearExpiredContainerInvitesJob {
    db_thread_pool: DbThreadPool,
    is_running: bool,
}

impl ClearExpiredContainerInvitesJob {
    pub fn new(db_thread_pool: DbThreadPool) -> Self {
        Self {
            db_thread_pool,
            is_running: false,
        }
    }
}

#[async_trait]
impl Job for ClearExpiredContainerInvitesJob {
    fn name(&self) -> &'static str {
        "Clear Expired Container Invites"
    }

    fn is_ready(&self) -> bool {
        !self.is_running
    }

    async fn execute(&mut self) -> Result<(), JobError> {
        self.is_running = true;

        let dao = ContainerDao::new(&self.db_thread_pool);
        tokio::task::spawn_blocking(move || dao.delete_all_expired_invitations()).await??;

        self.is_running = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use entries_common::db::user;
    use entries_common::messages::NewUser;
    use entries_common::models::container::NewContainer;
    use entries_common::models::container_accept_key::NewContainerAcceptKey;
    use entries_common::models::container_share_invite::NewContainerShareInvite;
    use entries_common::schema::container_accept_keys;
    use entries_common::schema::container_share_invites;
    use entries_common::schema::containers;
    use entries_common::threadrand::SecureRng;

    use diesel::{QueryDsl, RunQueryDsl};
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    use crate::env;

    #[tokio::test]
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
                &new_user.recovery_key_hash_salt_for_encryption,
                &new_user.recovery_key_hash_salt_for_recovery_auth,
                new_user.recovery_key_hash_mem_cost_kib,
                new_user.recovery_key_hash_threads,
                new_user.recovery_key_hash_iterations,
                "",
                &new_user.encryption_key_encrypted_with_password,
                &new_user.encryption_key_encrypted_with_recovery_key,
                public_key_id,
                &new_user.public_key,
                &new_user.preferences_encrypted,
                new_user.preferences_version_nonce,
                &new_user.user_keystore_encrypted,
                new_user.user_keystore_version_nonce,
            )
            .unwrap();
        user_dao.verify_user_creation(user_id).unwrap();

        let new_container = NewContainer {
            id: Uuid::now_v7(),
            encrypted_blob: &[0; 4],
            version_nonce: SecureRng::next_i64(),
            modified_timestamp: SystemTime::now(),
        };

        diesel::insert_into(containers::table)
            .values(&new_container)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_container_share_invite_exp = NewContainerShareInvite {
            id: Uuid::now_v7(),
            recipient_user_email: &new_user.email,
            sender_public_key: &[0; 4],
            encryption_key_encrypted: &[0; 4],
            container_accept_private_key_encrypted: &[0; 4],
            container_info_encrypted: &[0; 4],
            sender_info_encrypted: &[0; 4],
            container_accept_key_info_encrypted: &[0; 4],
            container_accept_key_id_encrypted: &[0; 4],
            share_info_symmetric_key_encrypted: &[0; 4],
            recipient_public_key_id_used_by_sender: (&new_user.public_key_id).try_into().unwrap(),
            recipient_public_key_id_used_by_server: (&new_user.public_key_id).try_into().unwrap(),
            created_unix_timestamp_intdiv_five_million: 100,
        };

        diesel::insert_into(container_share_invites::table)
            .values(&new_container_share_invite_exp)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_container_accept_key_exp = NewContainerAcceptKey {
            key_id: Uuid::now_v7(),
            container_id: new_container.id,
            public_key: &[0; 4],
            expiration: SystemTime::now() - Duration::from_secs(100),
            read_only: false,
        };

        diesel::insert_into(container_accept_keys::table)
            .values(&new_container_accept_key_exp)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_container_share_invite_not_exp = NewContainerShareInvite {
            id: Uuid::now_v7(),
            recipient_user_email: &new_user.email,
            sender_public_key: &[0; 4],
            encryption_key_encrypted: &[0; 4],
            container_accept_private_key_encrypted: &[0; 4],
            container_info_encrypted: &[0; 4],
            sender_info_encrypted: &[0; 4],
            container_accept_key_info_encrypted: &[0; 4],
            container_accept_key_id_encrypted: &[0; 4],
            share_info_symmetric_key_encrypted: &[0; 4],
            recipient_public_key_id_used_by_sender: (&new_user.public_key_id).try_into().unwrap(),
            recipient_public_key_id_used_by_server: (&new_user.public_key_id).try_into().unwrap(),
            created_unix_timestamp_intdiv_five_million: i16::MAX,
        };

        diesel::insert_into(container_share_invites::table)
            .values(&new_container_share_invite_not_exp)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_container_accept_key_not_exp = NewContainerAcceptKey {
            key_id: Uuid::now_v7(),
            container_id: new_container.id,
            public_key: &[0; 4],
            expiration: SystemTime::now() + Duration::from_secs(100),
            read_only: false,
        };

        diesel::insert_into(container_accept_keys::table)
            .values(&new_container_accept_key_not_exp)
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let mut job = ClearExpiredContainerInvitesJob::new(env::testing::DB_THREAD_POOL.clone());

        assert_eq!(
            container_share_invites::table
                .find(new_container_share_invite_exp.id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            container_accept_keys::table
                .find((new_container_accept_key_exp.key_id, new_container.id))
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            container_share_invites::table
                .find(new_container_share_invite_not_exp.id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            container_accept_keys::table
                .find((new_container_accept_key_not_exp.key_id, new_container.id))
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        job.execute().await.unwrap();

        assert_eq!(
            container_share_invites::table
                .find(new_container_share_invite_exp.id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            container_accept_keys::table
                .find((new_container_accept_key_exp.key_id, new_container.id))
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            container_share_invites::table
                .find(new_container_share_invite_not_exp.id)
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            container_accept_keys::table
                .find((new_container_accept_key_not_exp.key_id, new_container.id))
                .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );
    }
}
