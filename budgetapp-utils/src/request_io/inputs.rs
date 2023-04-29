use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::hex::Hex;
use serde_with::serde_as;
use std::time::SystemTime;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

// TODO: Sort these struct defs alphabetically

#[derive(Clone, Debug, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
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
pub struct InputBudgetId {
    pub budget_id: Uuid,
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

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct InputUser {
    pub email: String,

    pub auth_string: String,

    #[serde_as(as = "Base64")]
    pub auth_string_salt: Vec<u8>,
    pub auth_string_memory_cost_kib: i32,
    pub auth_string_parallelism_factor: i32,
    pub auth_string_iters: i32,

    #[serde_as(as = "Base64")]
    pub password_encryption_salt: Vec<u8>,
    pub password_encryption_memory_cost_kib: i32,
    pub password_encryption_parallelism_factor: i32,
    pub password_encryption_iters: i32,

    #[serde_as(as = "Base64")]
    pub recovery_key_salt: Vec<u8>,
    pub recovery_key_memory_cost_kib: i32,
    pub recovery_key_parallelism_factor: i32,
    pub recovery_key_iters: i32,

    #[serde_as(as = "Base64")]
    pub encryption_key_encrypted_with_password: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub encryption_key_encrypted_with_recovery_key: Vec<u8>,

    #[serde_as(as = "Base64")]
    pub public_key: Vec<u8>,

    #[serde_as(as = "Base64")]
    pub preferences_encrypted: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub user_keystore_encrypted: Vec<u8>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditUserPrefs {
    #[serde_as(as = "Base64")]
    pub encrypted_blob: Vec<u8>,
    #[serde_as(as = "Hex")]
    pub expected_previous_data_hash: Vec<u8>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditUserKeystore {
    #[serde_as(as = "Base64")]
    pub encrypted_blob: Vec<u8>,
    #[serde_as(as = "Hex")]
    pub expected_previous_data_hash: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputOtp {
    pub otp: String,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct InputNewAuthStringAndEncryptedPassword {
    pub current_auth_string: String,
    pub new_auth_string: String,

    #[serde_as(as = "Base64")]
    pub auth_string_salt: Vec<u8>,

    pub auth_string_iters: i32,

    #[serde_as(as = "Base64")]
    pub encrypted_encryption_key: Vec<u8>,
}

// temp_id is an ID the client generates that allows the server to differentiate between
// categories when multiple are sent to the server simultaneously. The server doesn't have any
// other way of differentiating them because they are encrypted.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputCategoryWithTempId {
    pub temp_id: i32,

    #[serde_as(as = "Base64")]
    pub encrypted_blob: Vec<u8>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBudget {
    #[serde_as(as = "Base64")]
    pub encrypted_blob: Vec<u8>,

    #[serde_as(as = "Base64")]
    pub encryption_key_encrypted: Vec<u8>,

    pub categories: Vec<InputCategoryWithTempId>,

    #[serde_as(as = "Base64")]
    pub user_public_budget_key: Vec<u8>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditBudget {
    #[serde_as(as = "Base64")]
    pub encrypted_blob: Vec<u8>,
    #[serde_as(as = "Hex")]
    pub expected_previous_data_hash: Vec<u8>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserInvitationToBudget {
    pub recipient_user_email: String,
    #[serde_as(as = "Base64")]
    pub sender_public_key: Vec<u8>,

    #[serde_as(as = "Base64")]
    pub encryption_key_encrypted: Vec<u8>,
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

    #[serde_as(as = "Base64")]
    pub budget_share_public_key: Vec<u8>,

    pub expiration: SystemTime,
    pub read_only: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEntryId {
    pub entry_id: Uuid,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEncryptedBlob {
    #[serde_as(as = "Base64")]
    encrypted_blob: Vec<u8>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEntryAndCategory {
    #[serde_as(as = "Base64")]
    pub entry_encrypted_blob: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub category_encrypted_blob: Vec<u8>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditEntry {
    #[serde_as(as = "Base64")]
    pub encrypted_blob: Vec<u8>,
    #[serde_as(as = "Hex")]
    pub expected_previous_data_hash: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputCategoryId {
    pub category_id: Uuid,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditCategory {
    pub category_id: Uuid,

    #[serde_as(as = "Base64")]
    pub encrypted_blob: Vec<u8>,
    #[serde_as(as = "Hex")]
    pub expected_previous_data_hash: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputTime {
    pub time: SystemTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBudgetAccessTokenList {
    pub budget_access_tokens: Vec<String>,
}
