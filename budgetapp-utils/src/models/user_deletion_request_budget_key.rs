use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::user_deletion_request_budget_keys;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = user_deletion_request_budget_keys, primary_key(key_id))]
pub struct UserDeletionRequestBudgetKey {
    pub key_id: Uuid,
    pub deletion_request_id: Uuid,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = user_deletion_request_budget_keys, primary_key(key_id))]
pub struct NewUserDeletionRequestBudgetKey {
    pub key_id: Uuid,
    pub deletion_request_id: Uuid,
}
