use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::validators;

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
pub struct InputOptionalUserId {
    pub user_id: Option<Uuid>,
    pub is_buddy: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBuddyRequestId {
    pub buddy_request_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBudgetId {
    pub budget_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputShareEventId {
    pub share_event_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBudgetShareEventId {
    pub share_event_id: Uuid,
    pub budget_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputDateRange {
    pub start_date: SystemTime,
    pub end_date: SystemTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputUser {
    pub email: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    pub date_of_birth: SystemTime,
    pub currency: String,
}

impl InputUser {
    pub fn validate_email_address(&self) -> validators::Validity {
        validators::validate_email_address(&self.email)
    }

    pub fn validate_strong_password(&self, min_password_len: usize) -> validators::Validity {
        validators::validate_strong_password(
            &self.password,
            &self.email,
            &self.first_name,
            &self.last_name,
            min_password_len,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditUser {
    pub first_name: String,
    pub last_name: String,
    pub date_of_birth: SystemTime,
    pub currency: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RefreshToken {
    pub token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigninTokenOtpPair {
    pub signin_token: String,
    pub otp: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CurrentAndNewPasswordPair {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputCategory {
    pub id: i16,
    pub name: String,
    pub limit_cents: i64,
    pub color: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputBudget {
    pub name: String,
    pub description: Option<String>,
    pub categories: Vec<InputCategory>,
    pub start_date: SystemTime,
    pub end_date: SystemTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEditBudget {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub start_date: SystemTime,
    pub end_date: SystemTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserInvitationToBudget {
    pub invitee_user_id: Uuid,
    pub budget_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputEntry {
    pub budget_id: Uuid,
    pub amount_cents: i64,
    pub date: SystemTime,
    pub name: Option<String>,
    pub category: Option<i16>,
    pub note: Option<String>,
}
