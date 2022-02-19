use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    pub user_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBudgetId {
    pub budget_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputDateRange {
    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct InputCategory {
    pub id: i16,
    pub name: String,
    pub limit_cents: i64,
    pub color: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct InputBudget {
    pub name: String,
    pub description: Option<String>,
    pub categories: Vec<InputCategory>,
    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct InputEntry {
    pub budget_id: Uuid,
    pub amount_cents: i64,
    pub date: NaiveDate,
    pub name: Option<String>,
    pub category: Option<i16>,
    pub note: Option<String>,
}
