use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::schema::budgets;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = budgets)]
pub struct Budget {
    pub id: Uuid,
    pub encrypted_blob: Vec<u8>,
    pub encrypted_blob_sha1_hash: Vec<u8>,
    pub modified_timestamp: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = budgets)]
pub struct NewBudget<'a> {
    pub id: Uuid,
    pub encrypted_blob: &'a [u8],
    pub encrypted_blob_sha1_hash: &'a [u8],
    pub modified_timestamp: SystemTime,
}
