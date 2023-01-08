use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::user::User;
use crate::schema::user_notifications;

#[derive(Associations, Debug, Serialize, Deserialize, Identifiable, Queryable)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = user_notifications)]
pub struct UserNotification {
    pub id: Uuid,
    pub user_id: Uuid,

    pub is_pristine: bool,
    pub is_unread: bool,

    pub notification_type: String,
    pub payload: serde_json::Value,

    pub modified_timestamp: SystemTime,
    pub created_timestamp: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = user_notifications)]
pub struct NewUserNotification<'a> {
    pub id: Uuid,
    pub user_id: Uuid,

    pub is_pristine: bool,
    pub is_unread: bool,

    pub notification_type: &'a str,
    pub payload: &'a serde_json::Value,

    pub modified_timestamp: SystemTime,
    pub created_timestamp: SystemTime,
}
