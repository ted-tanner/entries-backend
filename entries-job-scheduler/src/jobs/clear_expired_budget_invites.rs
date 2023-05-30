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
