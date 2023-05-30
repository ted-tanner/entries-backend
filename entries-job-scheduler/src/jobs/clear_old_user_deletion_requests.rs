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
