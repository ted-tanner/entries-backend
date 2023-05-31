use entries_utils::db::budget::Dao as BudgetDao;
use entries_utils::db::DbThreadPool;

use async_trait::async_trait;

use crate::jobs::{Job, JobError};

pub struct ClearExpiredBudgetInvitesJob {
    db_thread_pool: DbThreadPool,
    is_running: bool,
}

impl ClearExpiredBudgetInvitesJob {
    pub fn new(db_thread_pool: DbThreadPool) -> Self {
        Self {
            db_thread_pool,
            is_running: false,
        }
    }
}

#[async_trait]
impl Job for ClearExpiredBudgetInvitesJob {
    fn name(&self) -> &'static str {
        "Clear Expired Budget Invites"
    }

    fn is_ready(&self) -> bool {
        !self.is_running
    }

    async fn execute(&mut self) -> Result<(), JobError> {
        self.is_running = true;

        let mut dao = BudgetDao::new(&self.db_thread_pool);
        tokio::task::spawn_blocking(move || dao.delete_all_expired_invitations()).await??;

        self.is_running = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use entries_utils::db::user;
    use entries_utils::models::budget::NewBudget;
    use entries_utils::models::budget_accept_key::NewBudgetAcceptKey;
    use entries_utils::models::budget_share_invite::NewBudgetShareInvite;
    use entries_utils::request_io::InputUser;
    use entries_utils::schema::budget_accept_keys;
    use entries_utils::schema::budget_share_invites;
    use entries_utils::schema::budgets;

    use diesel::{QueryDsl, RunQueryDsl};
    use rand::Rng;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    use crate::env;

    #[tokio::test]
    async fn test_execute() {
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

        let new_budget = NewBudget {
            id: Uuid::new_v4(),
            encrypted_blob: &[0; 4],
            encrypted_blob_sha1_hash: &[0; 4],
            modified_timestamp: SystemTime::now(),
        };

        diesel::insert_into(budgets::table)
            .values(&new_budget)
            .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_budget_share_invite_exp = NewBudgetShareInvite {
            id: Uuid::new_v4(),
            recipient_user_email: &new_user.email,
            sender_public_key: &[0; 4],
            encryption_key_encrypted: &[0; 4],
            budget_accept_private_key_encrypted: &[0; 4],
            budget_info_encrypted: &[0; 4],
            sender_info_encrypted: &[0; 4],
            budget_accept_key_info_encrypted: &[0; 4],
            budget_accept_key_id_encrypted: &[0; 4],
            share_info_symmetric_key_encrypted: &[0; 4],
            created_unix_timestamp_intdiv_five_million: 100,
        };

        diesel::insert_into(budget_share_invites::table)
            .values(&new_budget_share_invite_exp)
            .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_budget_accept_key_exp = NewBudgetAcceptKey {
            key_id: Uuid::new_v4(),
            budget_id: new_budget.id,
            public_key: &[0; 4],
            expiration: SystemTime::now() - Duration::from_secs(100),
            read_only: false,
        };

        diesel::insert_into(budget_accept_keys::table)
            .values(&new_budget_accept_key_exp)
            .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_budget_share_invite_not_exp = NewBudgetShareInvite {
            id: Uuid::new_v4(),
            recipient_user_email: &new_user.email,
            sender_public_key: &[0; 4],
            encryption_key_encrypted: &[0; 4],
            budget_accept_private_key_encrypted: &[0; 4],
            budget_info_encrypted: &[0; 4],
            sender_info_encrypted: &[0; 4],
            budget_accept_key_info_encrypted: &[0; 4],
            budget_accept_key_id_encrypted: &[0; 4],
            share_info_symmetric_key_encrypted: &[0; 4],
            created_unix_timestamp_intdiv_five_million: i16::MAX,
        };

        diesel::insert_into(budget_share_invites::table)
            .values(&new_budget_share_invite_not_exp)
            .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let new_budget_accept_key_not_exp = NewBudgetAcceptKey {
            key_id: Uuid::new_v4(),
            budget_id: new_budget.id,
            public_key: &[0; 4],
            expiration: SystemTime::now() + Duration::from_secs(100),
            read_only: false,
        };

        diesel::insert_into(budget_accept_keys::table)
            .values(&new_budget_accept_key_not_exp)
            .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let mut job = ClearExpiredBudgetInvitesJob::new(env::db::DB_THREAD_POOL.clone());

        assert_eq!(
            budget_share_invites::table
                .find(new_budget_share_invite_exp.id)
                .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            budget_accept_keys::table
                .find((new_budget_accept_key_exp.key_id, new_budget.id))
                .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            budget_share_invites::table
                .find(new_budget_share_invite_not_exp.id)
                .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            budget_accept_keys::table
                .find((new_budget_accept_key_not_exp.key_id, new_budget.id))
                .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        job.execute().await.unwrap();

        assert_eq!(
            budget_share_invites::table
                .find(new_budget_share_invite_exp.id)
                .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            budget_accept_keys::table
                .find((new_budget_accept_key_exp.key_id, new_budget.id))
                .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            0
        );

        assert_eq!(
            budget_share_invites::table
                .find(new_budget_share_invite_not_exp.id)
                .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );

        assert_eq!(
            budget_accept_keys::table
                .find((new_budget_accept_key_not_exp.key_id, new_budget.id))
                .execute(&mut env::db::DB_THREAD_POOL.get().unwrap())
                .unwrap(),
            1
        );
    }
}
