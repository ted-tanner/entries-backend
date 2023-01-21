use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::schema::blacklisted_tokens;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable)]
#[diesel(belongs_to(User, foreign_key = user_id, primary_key(token)))]
pub struct BlacklistedToken {
    pub token: String,
    pub user_id: Uuid,
    pub token_expiration_time: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = blacklisted_tokens, primary_key(token))]
pub struct NewBlacklistedToken<'a> {
    pub token: &'a str,
    pub user_id: Uuid,
    pub token_expiration_time: SystemTime,
}
