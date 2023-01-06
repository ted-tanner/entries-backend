use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::budget::Budget;
use crate::schema::categories;

#[derive(Clone, Debug, Serialize, Deserialize, Associations, Identifiable, Queryable)]
#[diesel(belongs_to(Budget, foreign_key = budget_id))]
#[diesel(table_name = categories)]
pub struct Category {
    pub id: Uuid,
    pub budget_id: Uuid,
    pub name: String,
    pub limit_cents: i64,
    pub color: String,
    pub modified_timestamp: SystemTime,
    pub created_timestamp: SystemTime,
}

#[derive(Clone, Debug, Insertable)]
#[diesel(table_name = categories)]
pub struct NewCategory<'a> {
    pub id: Uuid,
    pub budget_id: Uuid,
    pub name: &'a str,
    pub limit_cents: i64,
    pub color: &'a str,
    pub modified_timestamp: SystemTime,
    pub created_timestamp: SystemTime,
}
