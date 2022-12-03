use chrono::{NaiveDate, NaiveDateTime};
use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};

use crate::schema::budgets;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = budgets)]
pub struct Budget {
    pub id: uuid::Uuid,
    pub is_shared: bool,
    pub is_private: bool,
    pub is_deleted: bool,

    pub name: String,
    pub description: Option<String>,

    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
    pub latest_entry_time: NaiveDateTime,

    pub modified_timestamp: NaiveDateTime,
    pub created_timestamp: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = budgets)]
pub struct NewBudget<'a> {
    pub id: uuid::Uuid,
    pub is_shared: bool,
    pub is_private: bool,
    pub is_deleted: bool,

    pub name: &'a str,
    pub description: Option<&'a str>,

    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
    pub latest_entry_time: NaiveDateTime,

    pub modified_timestamp: NaiveDateTime,
    pub created_timestamp: NaiveDateTime,
}
