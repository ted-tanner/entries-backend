use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

// TODO: Sort these struct defs alphabetically
// TODO: Can these Strings be &str?

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialPair {
    pub email: String,
    pub auth_string: String,
    pub nonce: i32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEmail {
    pub email: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBuddyRequestId {
    pub buddy_request_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBudgetId {
    pub budget_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBudgetIdList {
    pub budget_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputShareInviteId {
    pub share_invite_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBudgetShareInviteId {
    pub share_invite_id: Uuid,
    pub budget_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputDateRange {
    pub start_date: u64,
    pub end_date: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputUser {
    pub email: String,

    pub auth_string: String,

    pub auth_string_salt: String,
    pub auth_string_iters: i32,

    pub password_encryption_salt: String,
    pub password_encryption_iters: i32,

    pub recovery_key_salt: String,
    pub recovery_key_iters: i32,

    pub encryption_key_user_password_encrypted: String,
    pub encryption_key_recovery_key_encrypted: String,

    pub public_rsa_key: String,
    pub private_rsa_key_encrypted: String,

    pub preferences_encrypted: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditUserPrefs {
    pub encrypted_blob_b64: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBuddyRequest {
    pub other_user_email: String,
    pub sender_name_encrypted_b64: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RefreshToken {
    pub token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigninTokenOtpPair {
    pub signin_token: String,
    pub otp: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputNewAuthStringAndEncryptedPassword {
    pub current_auth_string: String,

    pub new_auth_string: String,
    pub auth_string_salt: String,
    pub auth_string_iters: i32,

    pub encrypted_encryption_key: String,
}

// temp_id is an ID the client generates that allows the server to differentiate between
// categories when multiple are sent to the server simultaneously. The server doesn't have any
// other way of differentiating them because they are encrypted.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputCategoryWithTempId {
    pub temp_id: i32,
    pub encrypted_blob_b64: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBudget {
    pub encrypted_blob_b64: String,
    pub encryption_key_encrypted_b64: String,
    pub categories: Vec<InputCategoryWithTempId>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditBudget {
    pub budget_id: Uuid,
    pub encrypted_blob_b64: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserInvitationToBudget {
    pub budget_id: Uuid,
    pub budget_name_encrypted_b64: String,
    pub budget_encryption_key_encrypted_b64: String,
    pub recipient_user_email: String,
    pub read_only: bool,
    pub sender_name_encrypted_b64: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEntryId {
    pub entry_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEntry {
    pub budget_id: Uuid,
    pub encrypted_blob_b64: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEntryAndCategory {
    pub budget_id: Uuid,
    pub entry_encrypted_blob_b64: String,
    pub category_encrypted_blob_b64: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditEntry {
    pub entry_id: Uuid,
    pub encrypted_blob_b64: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputCategoryId {
    pub category_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputCategory {
    pub budget_id: Uuid,
    pub encrypted_blob_b64: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditCategory {
    pub category_id: Uuid,
    pub encrypted_blob_b64: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputTombstoneId {
    pub item_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputTime {
    pub time: SystemTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputToken {
    pub token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEncryptedBudgetKey {
    pub budget_id: Uuid,
    pub encrypted_key: String,
    pub is_encrypted_with_aes: bool,
}
