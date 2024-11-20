use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::budget::Budget;
use crate::schema::budget_access_keys;

#[derive(Clone, Debug, Serialize, Deserialize, Associations, Identifiable, Queryable)]
#[diesel(belongs_to(Budget, foreign_key = budget_id))]
#[diesel(table_name = budget_access_keys, primary_key(key_id, budget_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct BudgetAccessKey {
    pub key_id: Uuid,
    pub budget_id: Uuid,
    pub public_key: Vec<u8>,
    pub read_only: bool,
}

#[derive(Clone, Debug, Insertable)]
#[diesel(table_name = budget_access_keys, primary_key(key_id, budget_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewBudgetAccessKey<'a> {
    pub key_id: Uuid,
    pub budget_id: Uuid,
    pub public_key: &'a [u8],
    pub read_only: bool,
}
