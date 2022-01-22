use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::utils::validators;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialPair {
    pub email: String,
    pub password: String,
}

impl CredentialPair {
    pub fn validate_email_address(&self) -> validators::Validity {
        validators::validate_email_address(&self.email)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputUserId {
    pub user_id: uuid::Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputUser {
    pub email: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    pub date_of_birth: NaiveDate,
    pub currency: String,
}

impl InputUser {
    pub fn validate_email_address(&self) -> validators::Validity {
        validators::validate_email_address(&self.email)
    }

    pub fn validate_strong_password(&self) -> validators::Validity {
        validators::validate_strong_password(
            &self.password,
            &self.email,
            &self.first_name,
            &self.last_name,
            &self.date_of_birth,
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RefreshToken {
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SigninTokenOtpPair {
    pub signin_token: String,
    pub otp: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CurrentAndNewPasswordPair {
    pub current_password: String,
    pub new_password: String,
}
