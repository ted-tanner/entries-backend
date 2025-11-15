use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::schema::containers;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = containers)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Container {
    pub id: Uuid,
    pub encrypted_blob: Vec<u8>,
    pub version_nonce: i64,
    pub modified_timestamp: SystemTime,
    pub deleted_at: Option<SystemTime>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = containers)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewContainer<'a> {
    pub id: Uuid,
    pub encrypted_blob: &'a [u8],
    pub version_nonce: i64,
    pub modified_timestamp: SystemTime,
}
