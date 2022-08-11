use diesel::{QueryableByName, Insertable, Queryable};
use serde::{Deserialize, Serialize};

use crate::models::user::User;
use crate::schema::password_attempts;

#[derive(Debug, Serialize, Deserialize, Identifiable, Associations, Queryable, QueryableByName)]
#[table_name = "password_attempts"]
#[belongs_to(User, foreign_key = "user_id")]
pub struct PasswordAttempts {
    pub id: i32,
    pub user_id: uuid::Uuid,
    pub attempt_count: i16,
}

#[derive(Debug, Insertable)]
#[table_name = "password_attempts"]
pub struct NewPasswordAttempts {
    pub user_id: uuid::Uuid,
    pub attempt_count: i16,
}
