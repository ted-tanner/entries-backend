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

    pub fn get_job_last_run_timestamp(
        &mut self,
        name: &str,
    ) -> Result<Option<SystemTime>, DaoError> {
        Ok(job_registry
            .select(job_registry_fields::last_run_timestamp)
            .find(name)
            .get_result(&mut self.db_thread_pool.get()?)
            .optional()?)
    }

    pub fn set_job_last_run_timestamp(
        &mut self,
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
