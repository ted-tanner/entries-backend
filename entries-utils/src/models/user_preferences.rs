use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::user::User;
use crate::schema::user_preferences;

#[derive(Debug, Serialize, Deserialize, Identifiable, Associations, Queryable, QueryableByName)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = user_preferences, primary_key(user_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UserPreferences {
    pub user_id: Uuid,
    pub encrypted_blob: Vec<u8>,
    pub version_nonce: i64,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = user_preferences, primary_key(user_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewUserPreferences<'a> {
    pub user_id: Uuid,
    pub encrypted_blob: &'a [u8],
    pub version_nonce: i64,
}
