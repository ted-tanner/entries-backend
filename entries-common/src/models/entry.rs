use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::category::Category;
use crate::models::container::Container;

use crate::schema::entries;

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Associations, Identifiable, Queryable,
)]
#[diesel(belongs_to(Container, foreign_key = container_id))]
#[diesel(belongs_to(Category, foreign_key = category_id))]
#[diesel(table_name = entries)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Entry {
    pub id: Uuid,
    pub container_id: Uuid,

    pub category_id: Option<Uuid>,

    pub encrypted_blob: Vec<u8>,
    pub version_nonce: i64,

    pub modified_timestamp: SystemTime,
    pub deleted_at: Option<SystemTime>,
}

#[derive(Clone, Debug, Insertable)]
#[diesel(table_name = entries)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewEntry<'a> {
    pub id: Uuid,
    pub container_id: Uuid,

    pub category_id: Option<Uuid>,

    pub encrypted_blob: &'a [u8],
    pub version_nonce: i64,

    pub modified_timestamp: SystemTime,
}
