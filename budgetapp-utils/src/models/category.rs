use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::models::budget::Budget;
use crate::schema::categories;

#[derive(Clone, Debug, Serialize, Deserialize, Associations, Identifiable, Queryable)]
#[diesel(belongs_to(Budget, foreign_key = budget_id))]
#[diesel(table_name = categories)]
pub struct Category {
    pub pk: i32,
    pub budget_id: uuid::Uuid,
    pub is_deleted: bool,
    pub id: i16,
    pub name: String,
    pub limit_cents: i64,
    pub color: String,
    pub modified_timestamp: SystemTime,
    pub created_timestamp: SystemTime,
}

#[derive(Clone, Debug, Insertable)]
#[diesel(table_name = categories)]
pub struct NewCategory<'a> {
    pub budget_id: uuid::Uuid,
    pub is_deleted: bool,
    pub id: i16,
    pub name: &'a str,
    pub limit_cents: i64,
    pub color: &'a str,
    pub modified_timestamp: SystemTime,
    pub created_timestamp: SystemTime,
}
