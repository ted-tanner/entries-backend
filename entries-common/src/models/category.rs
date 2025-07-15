use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::container::Container;
use crate::schema::categories;

#[derive(Clone, Debug, Serialize, Deserialize, Associations, Identifiable, Queryable)]
#[diesel(belongs_to(Container, foreign_key = container_id))]
#[diesel(table_name = categories)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Category {
    pub id: Uuid,
    pub container_id: Uuid,
    pub encrypted_blob: Vec<u8>,
    pub version_nonce: i64,
    pub modified_timestamp: SystemTime,
}

#[derive(Clone, Debug, Insertable)]
#[diesel(table_name = categories)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewCategory<'a> {
    pub id: Uuid,
    pub container_id: Uuid,
    pub encrypted_blob: &'a [u8],
    pub version_nonce: i64,
    pub modified_timestamp: SystemTime,
}
