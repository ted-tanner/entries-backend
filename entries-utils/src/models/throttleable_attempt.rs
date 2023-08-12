use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::schema::throttleable_attempts;

#[derive(Clone, Debug, Serialize, Deserialize, Insertable, Queryable, QueryableByName)]
#[diesel(table_name = throttleable_attempts)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ThrottleableAttempt {
    pub identifier_hash: i64,
    pub attempt_count: i32,
    pub expiration_timestamp: SystemTime,
}

pub type NewThrottleableAttempt = ThrottleableAttempt;
