use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::hex::Hex;
use serde_with::serde_as;
use std::time::SystemTime;
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEmail {
    pub email: String,
}

// TODO: NewUser
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, ZeroizeOnDrop)]
pub struct InputUser {
    pub email: String,

    #[serde_as(as = "Base64")]
    pub auth_string: Vec<u8>,

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

// TODO: EncryptedBlobUpdate
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditUserPrefs {
    #[serde_as(as = "Base64")]
    pub encrypted_blob: Vec<u8>,
    #[serde_as(as = "Hex")]
    pub expected_previous_data_hash: Vec<u8>,
}

// TODO: EncryptedBlobUpdate
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

// TODO: RecoveryKeyUpdate
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, ZeroizeOnDrop)]
pub struct InputNewRecoveryKey {
    pub otp: String,

    #[serde_as(as = "Base64")]
    pub recovery_key_salt: Vec<u8>,
    pub recovery_key_memory_cost_kib: i32,
    pub recovery_key_parallelism_factor: i32,
    pub recovery_key_iters: i32,

    #[serde_as(as = "Base64")]
    pub encrypted_encryption_key: Vec<u8>,
}

// TODO: EncryptedBlobUpdate
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
    pub budget_info_encrypted: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub sender_info_encrypted: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub share_info_symmetric_key_encrypted: Vec<u8>,

    pub expiration: SystemTime,
    pub read_only: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEntryId {
    pub entry_id: Uuid,
}

// TODO: NewEncryptedBlob
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEncryptedBlob {
    #[serde_as(as = "Base64")]
    pub encrypted_blob: Vec<u8>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEncryptedBlobAndCategoryId {
    #[serde_as(as = "Base64")]
    pub encrypted_blob: Vec<u8>,
    pub category_id: Option<Uuid>,
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
    pub entry_id: Uuid,
    #[serde_as(as = "Base64")]
    pub encrypted_blob: Vec<u8>,
    #[serde_as(as = "Hex")]
    pub expected_previous_data_hash: Vec<u8>,
    pub category_id: Option<Uuid>,
}

// TODO: Just Uuid
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputCategoryId {
    pub category_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBudgetAccessTokenList {
    pub budget_access_tokens: Vec<String>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputPublicKey {
    #[serde_as(as = "Base64")]
    pub public_key: Vec<u8>,
}
