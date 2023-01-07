use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::schema::blacklisted_tokens;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable)]
#[diesel(belongs_to(User, foreign_key = user_id))]
pub struct BlacklistedToken {
    pub id: i32,
    pub token: String,
    pub user_id: Uuid,
    pub token_expiration_time: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = blacklisted_tokens)]
pub struct NewBlacklistedToken<'a> {
    pub token: &'a str,
    pub user_id: Uuid,
    pub token_expiration_time: SystemTime,
}
