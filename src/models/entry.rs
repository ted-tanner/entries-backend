use chrono::{NaiveDate, NaiveDateTime};
use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};

use crate::models::budget::Budget;
use crate::models::user::User;
use crate::schema::entries;

#[derive(Debug, Serialize, Deserialize, Associations, Identifiable, Queryable)]
#[belongs_to(User, foreign_key = "user_id")]
#[belongs_to(Budget, foreign_key = "budget_id")]
#[table_name = "entries"]
pub struct Entry {
    pub id: uuid::Uuid,
    pub budget_id: uuid::Uuid,
    pub user_id: uuid::Uuid,

    pub is_deleted: bool,

    pub amount_cents: i64,
    pub date: NaiveDate,
    pub name: Option<String>,
    pub category: Option<i16>,
    pub note: Option<String>,

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
    pub amount_cents: i64,
    pub date: NaiveDate,
    pub name: Option<&'a str>,
    pub category: Option<i16>,
    pub note: Option<&'a str>,

    pub modified_timestamp: NaiveDateTime,
    pub created_timestamp: NaiveDateTime,
}
