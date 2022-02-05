use chrono::{NaiveDate, NaiveDateTime};
use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};

use crate::schema::entries;
use crate::models::user::User;
use crate::models::budget::Budget;

#[derive(Debug, Serialize, Deserialize, Associations, Identifiable, Queryable)]
#[belongs_to(User, foreign_key="user_id")]
#[belongs_to(Budget, foreign_key="budget_id")]
#[table_name = "entries"]
pub struct Entry {
    pub id: uuid::Uuid,
    pub budget_id: uuid::Uuid,
    pub user_id: uuid::Uuid,

    pub is_deleted: bool,

    pub amount: f64,
    pub date: NaiveDate,
    pub name: String,
    pub category: i16,
    pub note: String,

    pub modified_timestamp: NaiveDateTime,
    pub created_timestamp: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[table_name = "entries"]
pub struct NewEntry<'a> {
    pub id: uuid::Uuid,
    pub budget_id: uuid::Uuid,
    pub user_id: uuid::Uuid,

    pub is_deleted: bool,
    pub amount: f64,
    pub date: NaiveDate,
    pub name: &'a str,
    pub category: i16,
    pub note: &'a str,

    pub modified_timestamp: NaiveDateTime,
    pub created_timestamp: NaiveDateTime,
}
