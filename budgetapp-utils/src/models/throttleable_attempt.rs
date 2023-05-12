use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::schema::throttleable_attempts;

#[derive(Clone, Debug, Serialize, Deserialize, Queryable, QueryableByName)]
#[diesel(table_name = throttleable_attempts)]
pub struct ThrottleableAttempt {
    pub identifier_hash: i64,
    pub attempt_count: i32,
    pub expiration_timestamp: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = throttleable_attempts)]
pub struct NewThrottleableAttempt {
    pub identifier_hash: i64,
    pub attempt_count: i32,
    pub expiration_timestamp: SystemTime,
}
