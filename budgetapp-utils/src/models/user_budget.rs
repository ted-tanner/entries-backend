use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::budget::Budget;
use crate::models::user::User;
use crate::schema::user_budgets;

#[derive(Debug, Serialize, Deserialize, Identifiable, Associations, Queryable)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(belongs_to(Budget, foreign_key = budget_id))]
#[diesel(table_name = user_budgets, primary_key(user_id, budget_id))]
pub struct UserBudget {
    pub user_id: Uuid,
    pub budget_id: Uuid,

    // Key should be re-encrypted with AES-256 rather than RSA at earliest possible moment
    // after exchange
    pub encryption_key_encrypted: Vec<u8>,
    pub encryption_key_is_encrypted_with_aes_not_rsa: bool,

    pub read_only: bool,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = user_budgets, primary_key(user_id, budget_id))]
pub struct NewUserBudget<'a> {
    pub user_id: Uuid,
    pub budget_id: Uuid,

    pub encryption_key_encrypted: &'a [u8],
    pub encryption_key_is_encrypted_with_aes_not_rsa: bool,

    pub read_only: bool,
}
