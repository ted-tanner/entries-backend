use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::budget::Budget;
use crate::schema::budget_accept_keys;

#[derive(Clone, Debug, Serialize, Deserialize, Associations, Identifiable, Queryable)]
#[diesel(belongs_to(Budget, foreign_key = budget_id))]
#[diesel(table_name = budget_accept_keys, primary_key(key_id, budget_id))]
pub struct BudgetAcceptKey {
    pub key_id: Uuid,
    pub budget_id: Uuid,
    pub public_key: Vec<u8>,
    pub expiration: SystemTime,
    pub read_only: bool,
}

#[derive(Clone, Debug, Insertable)]
#[diesel(table_name = budget_accept_keys, primary_key(key_id, budget_id))]
pub struct NewBudgetAcceptKey<'a> {
    pub key_id: Uuid,
    pub budget_id: Uuid,
    pub public_key: &'a [u8],
    pub expiration: SystemTime,
    pub read_only: bool,
}
