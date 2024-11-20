use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::schema::budgets;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = budgets)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Budget {
    pub id: Uuid,
    pub encrypted_blob: Vec<u8>,
    pub version_nonce: i64,
    pub modified_timestamp: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = budgets)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewBudget<'a> {
    pub id: Uuid,
    pub encrypted_blob: &'a [u8],
    pub version_nonce: i64,
    pub modified_timestamp: SystemTime,
}
