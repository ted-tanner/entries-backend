use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::hex::Hex;
use serde_with::serde_as;
use std::sync::Arc;
use std::time::SystemTime;
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, ZeroizeOnDrop)]
pub struct CredentialPair {
    #[zeroize(skip)]
    pub email: Arc<str>,

    #[serde_as(as = "Base64")]
    pub auth_string: Vec<u8>,
    pub nonce: i32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEmail {
    pub email: Arc<str>,
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
#[derive(Clone, Debug, Deserialize, Serialize, ZeroizeOnDrop)]
pub struct InputUser {
    #[zeroize(skip)]
    pub email: Arc<str>,

    #[serde_as(as = "Base64")]
    pub auth_string: Vec<u8>,

    #[serde_as(as = "Base64")]
    #[zeroize(skip)]
    pub auth_string_salt: Arc<[u8]>,
    pub auth_string_memory_cost_kib: i32,
    pub auth_string_parallelism_factor: i32,
    pub auth_string_iters: i32,

    #[serde_as(as = "Base64")]
    #[zeroize(skip)]
    pub password_encryption_salt: Arc<[u8]>,
    pub password_encryption_memory_cost_kib: i32,
    pub password_encryption_parallelism_factor: i32,
    pub password_encryption_iters: i32,

    #[serde_as(as = "Base64")]
    #[zeroize(skip)]
    pub recovery_key_salt: Arc<[u8]>,
    pub recovery_key_memory_cost_kib: i32,
    pub recovery_key_parallelism_factor: i32,
    pub recovery_key_iters: i32,

    #[serde_as(as = "Base64")]
    #[zeroize(skip)]
    pub encryption_key_encrypted_with_password: Arc<[u8]>,
    #[serde_as(as = "Base64")]
    #[zeroize(skip)]
    pub encryption_key_encrypted_with_recovery_key: Arc<[u8]>,

    #[serde_as(as = "Base64")]
    #[zeroize(skip)]
    pub public_key: Arc<[u8]>,

    #[serde_as(as = "Base64")]
    #[zeroize(skip)]
    pub preferences_encrypted: Arc<[u8]>,
    #[serde_as(as = "Base64")]
    #[zeroize(skip)]
    pub user_keystore_encrypted: Arc<[u8]>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditUserPrefs {
    #[serde_as(as = "Base64")]
    pub encrypted_blob: Arc<[u8]>,
    #[serde_as(as = "Hex")]
    pub expected_previous_data_hash: Arc<[u8]>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditUserKeystore {
    #[serde_as(as = "Base64")]
    pub encrypted_blob: Arc<[u8]>,
    #[serde_as(as = "Hex")]
    pub expected_previous_data_hash: Arc<[u8]>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputOtp {
    pub otp: Arc<str>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, ZeroizeOnDrop)]
pub struct InputNewAuthStringAndEncryptedPassword {
    #[zeroize(skip)]
    pub user_email: Arc<str>,
    #[zeroize(skip)]
    pub otp: Arc<str>,

    #[serde_as(as = "Base64")]
    pub new_auth_string: Vec<u8>,

    #[serde_as(as = "Base64")]
    #[zeroize(skip)]
    pub auth_string_salt: Arc<[u8]>,
    pub auth_string_memory_cost_kib: i32,
    pub auth_string_parallelism_factor: i32,
    pub auth_string_iters: i32,

    #[serde_as(as = "Base64")]
    #[zeroize(skip)]
    pub password_encryption_salt: Arc<[u8]>,
    pub password_encryption_memory_cost_kib: i32,
    pub password_encryption_parallelism_factor: i32,
    pub password_encryption_iters: i32,

    #[serde_as(as = "Base64")]
    #[zeroize(skip)]
    pub encrypted_encryption_key: Arc<[u8]>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, ZeroizeOnDrop)]
pub struct InputNewRecoveryKey {
    #[zeroize(skip)]
    pub otp: Arc<str>,

    #[serde_as(as = "Base64")]
    #[zeroize(skip)]
    pub recovery_key_salt: Arc<[u8]>,
    pub recovery_key_memory_cost_kib: i32,
    pub recovery_key_parallelism_factor: i32,
    pub recovery_key_iters: i32,

    #[serde_as(as = "Base64")]
    #[zeroize(skip)]
    pub encrypted_encryption_key: Arc<[u8]>,
}

// temp_id is an ID the client generates that allows the server to differentiate between
// categories when multiple are sent to the server simultaneously. The server doesn't have any
// other way of differentiating them because they are encrypted.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputCategoryWithTempId {
    pub temp_id: i32,

    #[serde_as(as = "Base64")]
    pub encrypted_blob: Arc<[u8]>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBudget {
    #[serde_as(as = "Base64")]
    pub encrypted_blob: Arc<[u8]>,

    #[serde_as(as = "Base64")]
    pub encryption_key_encrypted: Arc<[u8]>,
    pub categories: Vec<InputCategoryWithTempId>,

    #[serde_as(as = "Base64")]
    pub user_public_budget_key: Arc<[u8]>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditBudget {
    #[serde_as(as = "Base64")]
    pub encrypted_blob: Arc<[u8]>,
    #[serde_as(as = "Hex")]
    pub expected_previous_data_hash: Arc<[u8]>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserInvitationToBudget {
    pub recipient_user_email: Arc<str>,
    #[serde_as(as = "Base64")]
    pub sender_public_key: Arc<[u8]>,

    #[serde_as(as = "Base64")]
    pub encryption_key_encrypted: Arc<[u8]>,

    #[serde_as(as = "Base64")]
    pub budget_info_encrypted: Arc<[u8]>,
    #[serde_as(as = "Base64")]
    pub sender_info_encrypted: Arc<[u8]>,
    #[serde_as(as = "Base64")]
    pub share_info_symmetric_key_encrypted: Arc<[u8]>,

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
    pub encrypted_blob: Arc<[u8]>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEncryptedBlobAndCategoryId {
    #[serde_as(as = "Base64")]
    pub encrypted_blob: Arc<[u8]>,
    pub category_id: Option<Uuid>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEntryAndCategory {
    #[serde_as(as = "Base64")]
    pub entry_encrypted_blob: Arc<[u8]>,
    #[serde_as(as = "Base64")]
    pub category_encrypted_blob: Arc<[u8]>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditEntry {
    pub entry_id: Uuid,
    #[serde_as(as = "Base64")]
    pub encrypted_blob: Arc<[u8]>,
    #[serde_as(as = "Hex")]
    pub expected_previous_data_hash: Arc<[u8]>,
    pub category_id: Option<Uuid>,
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
    pub encrypted_blob: Arc<[u8]>,
    #[serde_as(as = "Hex")]
    pub expected_previous_data_hash: Arc<[u8]>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputTime {
    pub time: SystemTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBudgetAccessTokenList {
    pub budget_access_tokens: Vec<String>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputPublicKey {
    #[serde_as(as = "Base64")]
    pub public_key: Arc<[u8]>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBackupCode {
    pub code: Arc<str>,
}
