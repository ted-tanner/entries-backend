use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::schema::buddy_requests;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = buddy_requests)]
pub struct BuddyRequest {
    pub id: Uuid,

    pub recipient_user_id: Uuid,
    pub sender_user_id: Uuid,

    pub accepted: bool,

    pub created_timestamp: SystemTime,
    pub accepted_declined_timestamp: Option<SystemTime>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = buddy_requests)]
pub struct NewBuddyRequest {
    pub id: Uuid,

    pub recipient_user_id: Uuid,
    pub sender_user_id: Uuid,

    pub accepted: bool,

    pub created_timestamp: SystemTime,
    pub accepted_declined_timestamp: Option<SystemTime>,
}
