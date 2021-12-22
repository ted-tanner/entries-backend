use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};

use crate::models::user::User;
use crate::schema::blacklisted_tokens;

#[derive(Debug, Serialize, Deserialize, Identifiable, Associations, Queryable)]
#[belongs_to(User, foreign_key = "user_id")]
pub struct BlacklistedToken {
    pub id: i32,
    pub token: String,
    pub user_id: uuid::Uuid,
    pub token_expiration_epoch: i64,
}

#[derive(Debug, Insertable)]
#[table_name = "blacklisted_tokens"]
pub struct NewBlacklistedToken<'a> {
    pub token: &'a str,
    pub user_id: uuid::Uuid,
    pub token_expiration_epoch: i64,
}
