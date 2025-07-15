use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};

use uuid::Uuid;

use crate::schema::container_share_invites;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = container_share_invites)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ContainerShareInvite {
    pub id: Uuid,

    pub recipient_user_email: String,
    pub sender_public_key: Vec<u8>,

    pub encryption_key_encrypted: Vec<u8>,
    pub container_accept_private_key_encrypted: Vec<u8>,

    pub container_info_encrypted: Vec<u8>,
    pub sender_info_encrypted: Vec<u8>,
    pub container_accept_key_info_encrypted: Vec<u8>,
    pub container_accept_key_id_encrypted: Vec<u8>,
    pub share_info_symmetric_key_encrypted: Vec<u8>,

    pub recipient_public_key_id_used_by_sender: Uuid,
    pub recipient_public_key_id_used_by_server: Uuid,

    pub created_unix_timestamp_intdiv_five_million: i16,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = container_share_invites)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewContainerShareInvite<'a> {
    pub id: Uuid,

    pub recipient_user_email: &'a str,
    pub sender_public_key: &'a [u8],

    pub encryption_key_encrypted: &'a [u8],
    pub container_accept_private_key_encrypted: &'a [u8],

    pub container_info_encrypted: &'a [u8],
    pub sender_info_encrypted: &'a [u8],
    pub container_accept_key_info_encrypted: &'a [u8],
    pub container_accept_key_id_encrypted: &'a [u8],
    pub share_info_symmetric_key_encrypted: &'a [u8],

    pub recipient_public_key_id_used_by_sender: Uuid,
    pub recipient_public_key_id_used_by_server: Uuid,

    pub created_unix_timestamp_intdiv_five_million: i16,
}

#[derive(Debug, Queryable)]
pub struct ContainerShareInvitePublicData {
    pub id: Uuid,

    pub container_info_encrypted: Vec<u8>,
    pub sender_info_encrypted: Vec<u8>,
    pub share_info_symmetric_key_encrypted: Vec<u8>,

    pub container_accept_key_info_encrypted: Vec<u8>,
    pub container_accept_key_encrypted: Vec<u8>,
    pub container_accept_key_id_encrypted: Vec<u8>,

    pub recipient_public_key_id_used_by_sender: Uuid,
    pub recipient_public_key_id_used_by_server: Uuid,
}
