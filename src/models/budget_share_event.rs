use chrono::NaiveDateTime;
use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};

use crate::schema::budget_share_events;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = budget_share_events)]
pub struct BudgetShareEvent {
    pub id: uuid::Uuid,

    pub recipient_user_id: uuid::Uuid,
    pub sender_user_id: uuid::Uuid,

    pub budget_id: uuid::Uuid,
    pub accepted: bool,

    pub created_timestamp: NaiveDateTime,
    pub accepted_declined_timestamp: Option<NaiveDateTime>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = budget_share_events)]
pub struct NewBudgetShareEvent {
    pub id: uuid::Uuid,

    pub recipient_user_id: uuid::Uuid,
    pub sender_user_id: uuid::Uuid,

    pub budget_id: uuid::Uuid,
    pub accepted: bool,

    pub created_timestamp: NaiveDateTime,
    pub accepted_declined_timestamp: Option<NaiveDateTime>,
}
