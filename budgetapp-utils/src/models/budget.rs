use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::schema::budgets;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = budgets)]
pub struct Budget {
    pub id: uuid::Uuid,
    pub is_deleted: bool,

    pub name: String,
    pub description: Option<String>,

    pub start_date: SystemTime,
    pub end_date: SystemTime,
    pub latest_entry_time: SystemTime,

    pub modified_timestamp: SystemTime,
    pub created_timestamp: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = budgets)]
pub struct NewBudget<'a> {
    pub id: uuid::Uuid,
    pub is_deleted: bool,

    pub name: &'a str,
    pub description: Option<&'a str>,

    pub start_date: SystemTime,
    pub end_date: SystemTime,
    pub latest_entry_time: SystemTime,

    pub modified_timestamp: SystemTime,
    pub created_timestamp: SystemTime,
}
