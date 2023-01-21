use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::schema::tombstones;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = tombstones, primary_key(item_id, related_user_id))]
pub struct Tombstone {
    pub item_id: Uuid,
    pub related_user_id: Uuid,
    pub origin_table: String,
    pub deletion_timestamp: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = tombstones, primary_key(item_id, related_user_id))]
pub struct NewTombstone<'a> {
    pub item_id: Uuid,
    pub related_user_id: Uuid,
    pub origin_table: &'a str,
    pub deletion_timestamp: SystemTime,
}
