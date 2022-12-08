use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::schema::budget_share_events;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = budget_share_events)]
pub struct BudgetShareEvent {
    pub id: uuid::Uuid,

    pub recipient_user_id: uuid::Uuid,
    pub sender_user_id: uuid::Uuid,

    pub budget_id: uuid::Uuid,
    pub accepted: bool,

    pub created_timestamp: SystemTime,
    pub accepted_declined_timestamp: Option<SystemTime>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = budget_share_events)]
pub struct NewBudgetShareEvent {
    pub id: uuid::Uuid,

    pub recipient_user_id: uuid::Uuid,
    pub sender_user_id: uuid::Uuid,

    pub budget_id: uuid::Uuid,
    pub accepted: bool,

    pub created_timestamp: SystemTime,
    pub accepted_declined_timestamp: Option<SystemTime>,
}
