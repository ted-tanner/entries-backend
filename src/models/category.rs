use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};

use crate::models::budget::Budget;
use crate::schema::categories;

#[derive(Debug, Serialize, Deserialize, Associations, Identifiable, Queryable)]
#[belongs_to(Budget, foreign_key = "budget_id")]
#[table_name = "categories"]
pub struct Category {
    pub pk: i32,
    pub budget_id: uuid::Uuid,
    pub id: i16,
    pub name: String,
    pub limit_cents: i64,
    pub color: String,
}

#[derive(Debug, Insertable)]
#[table_name = "categories"]
pub struct NewCategory<'a> {
    pub budget_id: uuid::Uuid,
    pub id: i16,
    pub name: &'a str,
    pub limit_cents: i64,
    pub color: &'a str,
}
