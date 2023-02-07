use diesel::Queryable;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::category::Category;
use crate::models::entry::Entry;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputEmail {
    pub email: String,
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

#[derive(Clone, Debug, Serialize, Deserialize, Queryable)]
pub struct OutputBudgetIdAndEncryptionKey {
    pub budget_id: Uuid,
    pub encryption_key_encrypted: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Queryable)]
pub struct OutputBudgetShareInviteWithoutKey {
    pub id: Uuid,

    pub recipient_user_id: Uuid,
    pub sender_user_id: Uuid,
    pub budget_id: Uuid,
    pub budget_name_encrypted: String,

    pub sender_name_encrypted: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputEntryIdAndCategoryId {
    pub entry_id: Uuid,
    pub category_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputEntryId {
    pub entry_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputCategoryId {
    pub category_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize, Queryable)]
pub struct OutputTombstone {
    pub item_id: Uuid,
    pub origin_table: String,
    pub deletion_timestamp: SystemTime,
}

#[derive(Clone, Debug, Serialize, Deserialize, Queryable)]
pub struct OutputTombstoneDoesExist {
    pub does_exist: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Queryable)]
pub struct OutputVerificationEmailSent {
    pub email_sent: bool,
    pub email_token_lifetime_hours: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Queryable)]
pub struct OutputIsUserListedForDeletion {
    pub is_listed_for_deletion: bool,
}
