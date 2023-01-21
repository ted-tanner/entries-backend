use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::user::User;
use crate::schema::password_attempts;

#[derive(
    Clone, Debug, Serialize, Deserialize, Identifiable, Associations, Queryable, QueryableByName,
)]
#[diesel(table_name = password_attempts, primary_key(user_id))]
#[diesel(belongs_to(User, foreign_key = user_id))]
pub struct PasswordAttempts {
    pub user_id: Uuid,
    pub attempt_count: i16,
    pub expiration_time: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = password_attempts, primary_key(user_id))]
pub struct NewPasswordAttempts {
    pub user_id: Uuid,
    pub attempt_count: i16,
    pub expiration_time: SystemTime,
}
