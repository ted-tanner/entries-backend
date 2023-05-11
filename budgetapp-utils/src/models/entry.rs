use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::budget::Budget;
use crate::models::category::Category;

use crate::schema::entries;

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Associations, Identifiable, Queryable,
)]
#[diesel(belongs_to(Budget, foreign_key = budget_id))]
#[diesel(belongs_to(Category, foreign_key = category_id))]
#[diesel(table_name = entries)]
pub struct Entry {
    pub id: Uuid,
    pub budget_id: Uuid,

    pub category_id: Option<Uuid>,

    pub encrypted_blob: Vec<u8>,
    pub encrypted_blob_sha1_hash: Vec<u8>,

    pub modified_timestamp: SystemTime,
}

#[derive(Clone, Debug, Insertable)]
#[diesel(table_name = entries)]
pub struct NewEntry<'a> {
    pub id: Uuid,
    pub budget_id: Uuid,

    pub category_id: Option<Uuid>,

    pub encrypted_blob: &'a [u8],
    pub encrypted_blob_sha1_hash: &'a [u8],

    pub modified_timestamp: SystemTime,
}
