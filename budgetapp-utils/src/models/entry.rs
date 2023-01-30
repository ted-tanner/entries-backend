use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::budget::Budget;

use crate::schema::entries;

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Associations, Identifiable, Queryable,
)]
#[diesel(belongs_to(Budget, foreign_key = budget_id))]
#[diesel(table_name = entries)]
pub struct Entry {
    pub id: Uuid,
    pub budget_id: Uuid,
    pub encrypted_blob: String,
    pub modified_timestamp: SystemTime,
}

#[derive(Clone, Debug, Insertable)]
#[diesel(table_name = entries)]
pub struct NewEntry<'a> {
    pub id: Uuid,
    pub budget_id: Uuid,
    pub encrypted_blob: &'a str,
    pub modified_timestamp: SystemTime,
}
