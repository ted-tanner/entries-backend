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
    pub is_deleted: bool,

    pub name: String,
    pub description: Option<String>,
    pub categories: Vec<Category>,
    pub entries: Vec<Entry>,

    pub start_date: SystemTime,
    pub end_date: SystemTime,
    pub latest_entry_time: SystemTime,

    pub modified_timestamp: SystemTime,
    pub created_timestamp: SystemTime,
}
