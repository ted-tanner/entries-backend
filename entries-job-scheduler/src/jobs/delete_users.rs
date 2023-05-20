use entries_utils::db::user::Dao as UserDao;
use entries_utils::db::DbThreadPool;

use async_trait::async_trait;
use futures::future;
use std::time::{Duration, SystemTime};

use crate::jobs::{Job, JobError};

// TODO: Test
pub struct DeleteUsersJob {
    pub job_frequency: Duration,
    db_thread_pool: DbThreadPool,
    is_running: bool,
    last_run_time: SystemTime,
}

impl DeleteUsersJob {
    pub fn new(
        job_frequency: Duration,
        last_run_time: SystemTime,
        db_thread_pool: DbThreadPool,
    ) -> Self {
        Self {
            job_frequency,
            db_thread_pool,
            is_running: false,
            last_run_time,
        }
    }

    pub fn name() -> &'static str {
        "Delete Users"
    }
}

#[async_trait]
impl Job for DeleteUsersJob {
    fn name(&self) -> &'static str {
        Self::name()
    }

    fn run_frequency(&self) -> Duration {
        self.job_frequency
    }

    fn last_run_time(&self) -> SystemTime {
        self.last_run_time
    }

    fn set_last_run_time(&mut self, time: SystemTime) {
        self.last_run_time = time
    }

    fn is_running(&self) -> bool {
        self.is_running
    }

    fn set_running_state_not_running(&mut self) {
        self.is_running = false;
    }

    fn set_running_state_running(&mut self) {
        self.is_running = true;
    }

    fn get_db_thread_pool_ref(&self) -> &DbThreadPool {
        &self.db_thread_pool
    }

    async fn run_handler_func(&mut self) -> Result<(), JobError> {
        let mut dao = UserDao::new(&self.db_thread_pool);

        let users_ready_for_deletion =
            tokio::task::spawn_blocking(move || dao.get_all_users_ready_for_deletion()).await??;

        let mut delete_user_futures = Vec::new();

        for user in users_ready_for_deletion {
            let mut dao = UserDao::new(&self.db_thread_pool);

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

        Ok(())
    }
}
