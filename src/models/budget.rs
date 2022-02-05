use chrono::{NaiveDate, NaiveDateTime};
use diesel::{Insertable, Queryable};
use diesel::sql_types::Jsonb;
use serde::{Deserialize, Serialize};

use crate::schema::budgets;

#[derive(Debug, Serialize, Deserialize)]
pub struct Category {
    pub name: String,
    pub limit: f32,
    pub color: String,
}

#[derive(Debug, Serialize, Deserialize, AsExpression)]
#[sql_type = "Jsonb"]
pub struct Categories {
    pub category_list: Vec<Category>,
}

#[derive(Debug, Serialize, Deserialize, Associations, Identifiable, Queryable)]
#[table_name = "budgets"]
pub struct Budget {
    pub id: uuid::Uuid,
    pub is_shared: bool,
    pub is_private: bool,
    pub is_deleted: bool,

    pub name: String,
    pub description: Option<String>,
    pub categories: Categories,

    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
    pub latest_entry_time: NaiveDateTime,

    pub modified_timestamp: NaiveDateTime,
    pub created_timestamp: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[table_name = "budgets"]
pub struct NewBudget<'a> {
    pub id: uuid::Uuid,
    pub is_shared: bool,
    pub is_private: bool,
    pub is_deleted: bool,
    
    pub name: &'a str,
    pub description: &'a str,
    pub categories: Option<Categories>,

    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
    pub latest_entry_time: NaiveDateTime,

    pub modified_timestamp: NaiveDateTime,
    pub created_timestamp: NaiveDateTime,
}
