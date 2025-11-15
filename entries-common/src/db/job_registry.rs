use diesel::{dsl, ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl};
use std::time::SystemTime;

use crate::db::{DaoError, DbThreadPool};
use crate::models::job_registry_item::NewJobRegistryItem;
use crate::schema::job_registry as job_registry_fields;
use crate::schema::job_registry::dsl::job_registry;

pub struct Dao {
    db_thread_pool: DbThreadPool,
}

impl Dao {
    pub fn new(db_thread_pool: &DbThreadPool) -> Self {
        Self {
            db_thread_pool: db_thread_pool.clone(),
        }
    }

    pub fn get_job_last_run_timestamp(&self, name: &str) -> Result<Option<SystemTime>, DaoError> {
        Ok(job_registry
            .select(job_registry_fields::last_run_timestamp)
            .find(name)
            .get_result(&mut self.db_thread_pool.get()?)
            .optional()?)
    }

    pub fn set_job_last_run_timestamp(
        &self,
        job_name: &str,
        timestamp: SystemTime,
    ) -> Result<(), DaoError> {
        let registry_item = NewJobRegistryItem {
            job_name,
            last_run_timestamp: timestamp,
        };

        dsl::insert_into(job_registry)
            .values(&registry_item)
            .on_conflict(job_registry_fields::job_name)
            .do_update()
            .set(job_registry_fields::last_run_timestamp.eq(timestamp))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils;
    use std::time::Duration;
    use uuid::Uuid;

    fn dao() -> Dao {
        Dao::new(test_utils::db_pool())
    }

    #[test]
    fn job_registry_persists_and_updates_timestamps() {
        let dao = dao();
        let job_name = format!("test-job-{}", Uuid::now_v7());

        assert!(dao.get_job_last_run_timestamp(&job_name).unwrap().is_none());

        let timestamp = SystemTime::now();
        dao.set_job_last_run_timestamp(&job_name, timestamp)
            .unwrap();

        let stored = dao.get_job_last_run_timestamp(&job_name).unwrap();
        assert_eq!(stored, Some(timestamp));

        let new_timestamp = timestamp + Duration::from_secs(60);
        dao.set_job_last_run_timestamp(&job_name, new_timestamp)
            .unwrap();

        let updated = dao.get_job_last_run_timestamp(&job_name).unwrap();
        assert_eq!(updated, Some(new_timestamp));
    }
}
