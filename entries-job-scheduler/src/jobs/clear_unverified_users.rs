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
