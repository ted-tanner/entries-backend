use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};

use crate::models::user::User;
use crate::schema::otp_attempts;

#[derive(Debug, Serialize, Deserialize, Identifiable, Associations, Queryable, QueryableByName)]
#[table_name = "otp_attempts"]
#[belongs_to(User, foreign_key = "user_id")]
pub struct OtpAttempts {
    pub id: i32,
    pub user_id: uuid::Uuid,
    pub attempt_count: i16,
}

#[derive(Debug, Insertable)]
#[table_name = "otp_attempts"]
pub struct NewOtpAttempts {
    pub user_id: uuid::Uuid,
    pub attempt_count: i16,
}
