use entries_utils::db::auth::Dao as AuthDao;
use entries_utils::db::DbThreadPool;

use async_trait::async_trait;

use crate::jobs::{Job, JobError};

pub struct ClearExpiredOtpsJob {
    db_thread_pool: DbThreadPool,
    is_running: bool,
}

impl ClearExpiredOtpsJob {
    pub fn new(db_thread_pool: DbThreadPool) -> Self {
        Self {
            db_thread_pool,
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

        let mut dao = AuthDao::new(&self.db_thread_pool);
        tokio::task::spawn_blocking(move || dao.delete_all_expired_otps()).await??;

        self.is_running = false;
        Ok(())
    }
}
