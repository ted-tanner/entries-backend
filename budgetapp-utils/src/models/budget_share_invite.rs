use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};

use uuid::Uuid;

use crate::schema::budget_share_invites;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = budget_share_invites)]
pub struct BudgetShareInvite {
    pub id: Uuid,

    pub recipient_user_id: Uuid,
    pub sender_user_id: Uuid,
    pub budget_id: Uuid,

    pub budget_name_encrypted: String,
    pub sender_name_encrypted: Option<String>,

    // This should never get sent to the recipient user until the invite has been accepted
    pub encryption_key_encrypted: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = budget_share_invites)]
pub struct NewBudgetShareInvite<'a> {
    pub id: Uuid,

    pub recipient_user_id: Uuid,
    pub sender_user_id: Uuid,
    pub budget_id: Uuid,

    pub budget_name_encrypted: &'a str,
    pub sender_name_encrypted: Option<&'a str>,

    pub encryption_key_encrypted: &'a str,
}
