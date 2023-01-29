use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::category::Category;
use crate::models::entry::Entry;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputEmail {
    email: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputUserPrivate {
    pub id: Uuid,

    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub date_of_birth: SystemTime,
    pub currency: String,

    pub modified_timestamp: SystemTime,
    pub created_timestamp: SystemTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputUserForBuddies {
    pub id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub currency: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputUserPublic {
    pub id: Uuid,
    pub first_name: String,
    pub last_name: String,
    pub currency: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigninToken {
    pub signin_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub server_time: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputBudget {
    pub id: Uuid,

    pub encrypted_blob: String,
    pub modified_timestamp: SystemTime,

    pub categories: Vec<Category>,
    pub entries: Vec<Entry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputBudgetFrameCategory {
    pub temp_id: i32,
    pub real_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputBudgetFrame {
    pub id: Uuid,
    pub categories: Vec<OutputBudgetFrameCategory>,
    pub modified_timestamp: SystemTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputBudgetIdAndEncryptionKey {
    budget_id: Uuid,
    encryption_key_encrypted: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputBudgetShareInviteWithoutKey {
    pub id: Uuid,

    pub recipient_user_id: Uuid,
    pub sender_user_id: Uuid,
    pub budget_id: Uuid,

    pub sender_name_encrypted: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputEntryIdAndCategoryId {
    entry_id: Uuid,
    category_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputEntryId {
    entry_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputCategoryId {
    category_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputTombstone {
    item_id: Uuid,
    origin_table: String,
    deletion_timestamp: SystemTime,
}
