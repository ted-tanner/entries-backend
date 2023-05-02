use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};

use uuid::Uuid;

use crate::schema::budget_share_invites;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = budget_share_invites)]
pub struct BudgetShareInvite {
    pub id: Uuid,

    pub recipient_user_email: String,
    pub sender_public_key: Vec<u8>,

    pub encryption_key_encrypted: Vec<u8>,
    pub budget_accept_private_key_encrypted: Vec<u8>,

    pub budget_info_encrypted: Vec<u8>,
    pub sender_info_encrypted: Vec<u8>,
    pub budget_accept_private_key_info_encrypted: Vec<u8>,
    pub budget_accept_private_key_id_encrypted: Vec<u8>,
    pub share_info_symmetric_key_encrypted: Vec<u8>,

    pub created_unix_timestamp_intdiv_five_million: i16,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = budget_share_invites)]
pub struct NewBudgetShareInvite<'a> {
    pub id: Uuid,

    pub recipient_user_email: &'a str,
    pub sender_public_key: &'a [u8],

    pub encryption_key_encrypted: &'a [u8],
    pub budget_accept_private_key_encrypted: &'a [u8],

    pub budget_info_encrypted: &'a [u8],
    pub sender_info_encrypted: &'a [u8],
    pub budget_accept_private_key_info_encrypted: &'a [u8],
    pub budget_accept_private_key_id_encrypted: &'a [u8],
    pub share_info_symmetric_key_encrypted: &'a [u8],

    pub created_unix_timestamp_intdiv_five_million: i16,
}
