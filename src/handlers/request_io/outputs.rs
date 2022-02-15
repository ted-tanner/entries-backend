use chrono::{NaiveDate, NaiveDateTime};
use serde::{Deserialize, Serialize};

use crate::models::category::Category;
use crate::models::entry::Entry;

#[derive(Debug, Serialize, Deserialize)]
pub struct OutputUserPrivate {
    pub id: uuid::Uuid,
    pub is_active: bool,

    pub is_premium: bool,
    pub premium_expiration: Option<NaiveDate>,

    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub date_of_birth: NaiveDate,
    pub currency: String,

    pub modified_timestamp: NaiveDateTime,
    pub created_timestamp: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutputUserPublic {
    pub id: uuid::Uuid,
    pub is_premium: bool,
    pub is_active: bool,
    pub first_name: String,
    pub last_name: String,
    pub currency: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SigninToken {
    pub signin_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutputBudget {
    pub id: uuid::Uuid,
    pub is_shared: bool,
    pub is_private: bool,
    pub is_deleted: bool,

    pub name: String,
    pub description: Option<String>,
    pub categories: Vec<Category>,
    pub entries: Vec<Entry>,

    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
    pub latest_entry_time: NaiveDateTime,

    pub modified_timestamp: NaiveDateTime,
    pub created_timestamp: NaiveDateTime,
}
