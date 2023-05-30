use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::user::User;
use crate::schema::user_backup_codes;

#[derive(Debug, Serialize, Deserialize, Identifiable, Associations, Queryable)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = user_backup_codes, primary_key(user_id, code))]
pub struct UserBackupCode {
    pub user_id: Uuid,
    pub code: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = user_backup_codes, primary_key(user_id, code))]
pub struct NewUserBackupCode<'a> {
    pub user_id: Uuid,
    pub code: &'a str,
}
