use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};

use uuid::Uuid;

use crate::schema::budget_share_invites;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = budget_share_invites)]
pub struct BudgetShareInvite {
    pub id: Uuid,

    pub recipient_user_email: String,
    pub sender_user_email: String,
    pub budget_id: Uuid,

    pub budget_name_encrypted: Vec<u8>,
    pub sender_name_encrypted: Option<Vec<u8>>,

    pub read_only: bool,

    // This should never get sent to the recipient user until the invite has been accepted
    pub encryption_key_encrypted: Vec<u8>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = budget_share_invites)]
pub struct NewBudgetShareInvite<'a> {
    pub id: Uuid,

    pub recipient_user_email: &'a str,
    pub sender_user_email: &'a str,
    pub budget_id: Uuid,

    pub budget_name_encrypted: &'a [u8],
    pub sender_name_encrypted: Option<&'a [u8]>,

    pub read_only: bool,

    pub encryption_key_encrypted: &'a [u8],
}
