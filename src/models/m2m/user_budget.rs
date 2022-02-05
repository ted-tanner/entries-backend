use chrono::NaiveDateTime;
use diesel::{Insertable, Queryable};

use serde::{Deserialize, Serialize};

use crate::models::budget::Budget;
use crate::models::user::User;
use crate::schema::user_budgets;

#[derive(Debug, Serialize, Deserialize, Identifiable, Associations, Queryable)]
#[belongs_to(User, foreign_key = "user_id")]
#[belongs_to(Budget, foreign_key = "budget_id")]
#[table_name = "user_budgets"]
pub struct UserBudget {
    pub id: i32,
    pub created_timestamp: NaiveDateTime,
    pub user_id: uuid::Uuid,
    pub budget_id: uuid::Uuid,
}

#[derive(Debug, Insertable)]
#[table_name = "user_budgets"]
pub struct NewUserBudget {
    pub created_timestamp: NaiveDateTime,
    pub user_id: uuid::Uuid,
    pub budget_id: uuid::Uuid,
}
