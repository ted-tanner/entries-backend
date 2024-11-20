use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::schema::blacklisted_tokens;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable)]
#[diesel(primary_key(token_signature))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct BlacklistedToken {
    pub token_signature: Vec<u8>,
    pub token_expiration: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = blacklisted_tokens)]
#[diesel(primary_key(token_signature))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewBlacklistedToken<'a> {
    pub token_signature: &'a [u8],
    pub token_expiration: SystemTime,
}
