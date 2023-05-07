use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::models::user::User;
use crate::schema::user_lookup_attempts;

#[derive(
    Clone, Debug, Serialize, Deserialize, Identifiable, Associations, Queryable, QueryableByName,
)]
#[diesel(table_name = user_lookup_attempts, primary_key(user_email))]
#[diesel(belongs_to(User, foreign_key = user_email))]
pub struct UserLookupAttempts {
    pub user_email: String,
    pub attempt_count: i16,
    pub expiration_time: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = user_lookup_attempts, primary_key(user_email))]
pub struct NewUserLookupAttempts<'a> {
    pub user_email: &'a str,
    pub attempt_count: i16,
    pub expiration_time: SystemTime,
}
