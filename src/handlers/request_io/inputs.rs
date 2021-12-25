use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::db_utils;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialPair {
    pub email: String,
    pub password: String,
}

impl CredentialPair {
    pub fn validate_email_address(&self) -> bool {
        return db_utils::validate_email_address(&self.email);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputUserId {
    pub user_id: uuid::Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputUser {
    pub email: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    pub date_of_birth: NaiveDate,
    pub currency: String,
}

impl InputUser {
    pub fn validate_email_address(&self) -> bool {
        db_utils::validate_email_address(&self.email)
    }

    pub fn validate_strong_password(&self) -> db_utils::PasswordValidity {
        db_utils::validate_strong_password(self)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RefreshToken(pub String);

#[derive(Debug, Deserialize, Serialize)]
pub struct OldPassword(pub String);

#[derive(Debug, Deserialize, Serialize)]
pub struct NewPassword(pub String);
