use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::user::User;
use crate::schema::user_preferences;

#[derive(Debug, Serialize, Deserialize, Identifiable, Associations, Queryable, QueryableByName)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = user_preferences, primary_key(user_id))]
pub struct UserPreferences {
    pub user_id: Uuid,
    pub encrypted_blob: String,
    pub modified_timestamp: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = user_preferences, primary_key(user_id))]
pub struct NewUserPreferences<'a> {
    pub user_id: Uuid,
    pub encrypted_blob: &'a str,
    pub modified_timestamp: SystemTime,
}
