use diesel::Queryable;
use serde::Serialize;
use serde_with::base64::Base64;
use serde_with::serde_as;
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::category::Category;
use crate::models::entry::Entry;

#[derive(Clone, Debug, Serialize)]
pub struct SigninToken {
    pub signin_token: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub server_time: u128,
}

#[serde_as]
#[derive(Clone, Debug, Serialize)]
pub struct OutputBudget {
    pub id: Uuid,

    #[serde_as(as = "Base64")]
    pub encrypted_blob: Vec<u8>,

    pub modified_timestamp: SystemTime,

    pub categories: Vec<Category>,
    pub entries: Vec<Entry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OutputBudgetFrameCategory {
    pub temp_id: i32,
    pub real_id: Uuid,
}

#[derive(Clone, Debug, Serialize)]
pub struct OutputBudgetFrame {
    pub id: Uuid,
    pub categories: Vec<OutputBudgetFrameCategory>,
    pub modified_timestamp: SystemTime,
}

#[serde_as]
#[derive(Clone, Debug, Serialize)]
pub struct OutputBudgetIdAndEncryptionKey {
    pub budget_id: Uuid,
    pub budget_access_key_id: Uuid,

    #[serde_as(as = "Base64")]
    pub encryption_key_encrypted: Vec<u8>,

    pub read_only: bool,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Queryable)]
pub struct OutputBudgetShareInviteWithoutKey {
    #[serde_as(as = "Base64")]
    pub budget_accept_private_key_encrypted: Vec<u8>,

    #[serde_as(as = "Base64")]
    pub budget_info_encrypted: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub sender_info_encrypted: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub budget_accept_private_key_info_encrypted: Vec<u8>,

    #[serde_as(as = "Base64")]
    pub share_info_symmetric_key_encrypted: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OutputEntryIdAndCategoryId {
    pub entry_id: Uuid,
    pub category_id: Uuid,
}

#[derive(Clone, Debug, Serialize)]
pub struct OutputEntryId {
    pub entry_id: Uuid,
}

#[derive(Clone, Debug, Serialize)]
pub struct OutputCategoryId {
    pub category_id: Uuid,
}

#[derive(Clone, Debug, Serialize)]
pub struct OutputVerificationEmailSent {
    pub email_sent: bool,
    pub email_token_lifetime_hours: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct OutputBackupCodesAndVerificationEmailSent<'a> {
    pub email_sent: bool,
    pub email_token_lifetime_hours: u64,
    pub backup_codes: &'a [String],
}

#[derive(Clone, Debug, Serialize)]
pub struct OutputBackupCodes<'a> {
    pub backup_codes: &'a [String],
}

#[derive(Clone, Debug, Serialize)]
pub struct OutputIsUserListedForDeletion {
    pub is_listed_for_deletion: bool,
}

#[serde_as]
#[derive(Clone, Debug, Serialize)]
pub struct OutputSigninNonceAndHashParams {
    #[serde_as(as = "Base64")]
    pub auth_string_salt: Vec<u8>,
    pub auth_string_memory_cost_kib: i32,
    pub auth_string_parallelism_factor: i32,
    pub auth_string_iters: i32,

    pub nonce: i32,
}

#[derive(Clone, Debug, Serialize)]
pub struct OutputInvitationId {
    pub invitation_id: Uuid,
}

#[serde_as]
#[derive(Clone, Debug, Serialize)]
pub struct OutputPublicKey {
    #[serde_as(as = "Base64")]
    pub public_key: Vec<u8>,
}
