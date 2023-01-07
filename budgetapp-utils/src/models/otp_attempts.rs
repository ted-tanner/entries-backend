use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::user::User;
use crate::schema::otp_attempts;

#[derive(
    Clone, Debug, Serialize, Deserialize, Identifiable, Associations, Queryable, QueryableByName,
)]
#[diesel(table_name = otp_attempts)]
#[diesel(belongs_to(User, foreign_key = user_id))]
pub struct OtpAttempts {
    pub id: i32,
    pub user_id: Uuid,
    pub attempt_count: i16,
    pub expiration_time: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = otp_attempts)]
pub struct NewOtpAttempts {
    pub user_id: Uuid,
    pub attempt_count: i16,
    pub expiration_time: SystemTime,
}
