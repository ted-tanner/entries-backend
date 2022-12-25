use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::schema::user_tombstones;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = user_tombstones)]
pub struct UserTombstone {
    pub id: i32,
    pub user_id: Uuid,
    pub deletion_request_time: SystemTime,
    pub deletion_time: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = user_tombstones)]
pub struct NewUserTombstone {
    pub user_id: Uuid,
    pub deletion_request_time: SystemTime,
    pub deletion_time: SystemTime,
}
