use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::schema::job_registry;

#[derive(Clone, Debug, Serialize, Deserialize, Identifiable, Queryable)]
#[diesel(table_name = job_registry, primary_key(job_name))]
pub struct JobRegistryItem {
    pub job_name: String,
    pub last_run_timestamp: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = job_registry, primary_key(job_name))]
pub struct NewJobRegistryItem<'a> {
    pub job_name: &'a str,
    pub last_run_timestamp: SystemTime,
}
