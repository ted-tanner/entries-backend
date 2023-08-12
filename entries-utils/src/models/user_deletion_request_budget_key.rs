use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::schema::user_deletion_request_budget_keys;

#[derive(Debug, Serialize, Deserialize, Identifiable, Insertable, Queryable, QueryableByName)]
#[diesel(table_name = user_deletion_request_budget_keys, primary_key(key_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UserDeletionRequestBudgetKey {
    pub key_id: Uuid,
    pub user_id: Uuid,
    pub delete_me_time: SystemTime,
}

pub type NewUserDeletionRequestBudgetKey = UserDeletionRequestBudgetKey;
