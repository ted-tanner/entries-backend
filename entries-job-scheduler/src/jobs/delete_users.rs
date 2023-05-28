use entries_utils::db::user::Dao as UserDao;
use entries_utils::db::DbThreadPool;

use async_trait::async_trait;
use futures::future;

use crate::jobs::{Job, JobError};

// TODO: Test
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

        self.is_running = false;
        Ok(())
    }
}
