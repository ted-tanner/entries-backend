use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::budget::Budget;
use crate::models::user::User;
use crate::schema::entries;

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Associations, Identifiable, Queryable,
)]
#[diesel(belongs_to(Budget, foreign_key = budget_id))]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = entries)]
pub struct Entry {
    pub id: Uuid,
    pub budget_id: Uuid,
    pub user_id: Option<Uuid>,

    pub is_deleted: bool,

    pub amount_cents: i64,
    pub date: SystemTime,
    pub name: Option<String>,
    pub note: Option<String>,

    pub category_id: Option<Uuid>,

    pub modified_timestamp: SystemTime,
    pub created_timestamp: SystemTime,
}

#[derive(Clone, Debug, Insertable)]
#[diesel(table_name = entries)]
pub struct NewEntry<'a> {
    pub id: Uuid,
    pub budget_id: Uuid,
    pub user_id: Uuid,

    pub is_deleted: bool,

    pub amount_cents: i64,
    pub date: SystemTime,
    pub name: Option<&'a str>,
    pub note: Option<&'a str>,

    pub category_id: Option<Uuid>,

    pub modified_timestamp: SystemTime,
    pub created_timestamp: SystemTime,
}
