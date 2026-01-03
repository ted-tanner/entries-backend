use entries_common::db::auth::Dao as AuthDao;
use entries_common::db::DbAsyncPool;

use async_trait::async_trait;

use crate::jobs::{Job, JobError};

pub struct ClearExpiredOtpsJob {
    db_async_pool: DbAsyncPool,
    is_running: bool,
}

impl ClearExpiredOtpsJob {
    pub fn new(db_async_pool: DbAsyncPool) -> Self {
        Self {
            db_async_pool,
            is_running: false,
        }
    }
}

#[async_trait]
impl Job for ClearExpiredOtpsJob {
    fn name(&self) -> &'static str {
        "Clear Expired Otps"
    }

    fn is_ready(&self) -> bool {
        !self.is_running
    }

    async fn execute(&mut self) -> Result<(), JobError> {
        self.is_running = true;

        let dao = AuthDao::new(&self.db_async_pool);
        dao.delete_all_expired_otps().await?;

        self.is_running = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use entries_common::db::user;
    use entries_common::messages::NewUser;
    use entries_common::models::user_otp::NewUserOtp;
    use entries_common::schema::user_otps;
    use entries_common::threadrand::SecureRng;

    use diesel::{ExpressionMethods, QueryDsl};
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    use crate::env;

    #[tokio::test]
    #[ignore = "Needs async pool setup and sync pool removal"]
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

        let user_dao = user::Dao::new(&env::testing::DB_ASYNC_POOL);

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

        let new_otp_exp = NewUserOtp {
            user_email: &new_user1.email,
            otp: "ABC123",
            expiration: SystemTime::now() - Duration::from_nanos(1),
        };

        diesel_async::RunQueryDsl::execute(
            diesel::insert_into(user_otps::table).values(&new_otp_exp),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let new_otp_not_exp = NewUserOtp {
            user_email: &new_user2.email,
            otp: "ABC456",
            expiration: SystemTime::now() + Duration::from_secs(100),
        };

        diesel_async::RunQueryDsl::execute(
            diesel::insert_into(user_otps::table).values(&new_otp_not_exp),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let mut job = ClearExpiredOtpsJob::new(env::testing::DB_ASYNC_POOL.clone());

        let count = diesel_async::RunQueryDsl::execute(
            user_otps::table
                .find(&new_user1.email)
                .filter(user_otps::otp.eq(&new_otp_exp.otp)),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(count, 1);

        let count = diesel_async::RunQueryDsl::execute(
            user_otps::table
                .find(&new_user2.email)
                .filter(user_otps::otp.eq(&new_otp_not_exp.otp)),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(count, 1);

        job.execute().await.unwrap();

        let count = diesel_async::RunQueryDsl::execute(
            user_otps::table
                .find(&new_user1.email)
                .filter(user_otps::otp.eq(&new_otp_exp.otp)),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(count, 0);

        let count = diesel_async::RunQueryDsl::execute(
            user_otps::table
                .find(&new_user2.email)
                .filter(user_otps::otp.eq(&new_otp_not_exp.otp)),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(count, 1);
    }
}
