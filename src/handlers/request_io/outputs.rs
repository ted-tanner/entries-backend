use chrono::{NaiveDate, NaiveDateTime};
use serde::{Deserialize, Serialize};

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
