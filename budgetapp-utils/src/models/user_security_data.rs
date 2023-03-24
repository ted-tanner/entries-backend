use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::user::User;
use crate::schema::user_security_data;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, Associations, QueryableByName)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = user_security_data, primary_key(user_id))]
pub struct UserSecurityData {
    pub user_id: Uuid,

    pub auth_string_hash: String,

    pub auth_string_salt: Vec<u8>,
    pub auth_string_iters: i32,

    pub password_encryption_salt: Vec<u8>,
    pub password_encryption_iters: i32,

    pub recovery_key_salt: Vec<u8>,
    pub recovery_key_iters: i32,

    pub encryption_key_encrypted_with_password: Vec<u8>,
    pub encryption_key_encrypted_with_recovery_key: Vec<u8>,

    pub public_rsa_key: Vec<u8>,
    pub rsa_key_created_timestamp: SystemTime,

    pub last_token_refresh_timestamp: SystemTime,

    pub modified_timestamp: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = user_security_data, primary_key(user_id))]
pub struct NewUserSecurityData<'a> {
    pub user_id: Uuid,

    pub auth_string_hash: &'a str,

    pub auth_string_salt: &'a [u8],
    pub auth_string_iters: i32,

    pub password_encryption_salt: &'a [u8],
    pub password_encryption_iters: i32,

    pub recovery_key_salt: &'a [u8],
    pub recovery_key_iters: i32,

    pub encryption_key_encrypted_with_password: &'a [u8],
    pub encryption_key_encrypted_with_recovery_key: &'a [u8],

    pub public_rsa_key: &'a [u8],
    pub rsa_key_created_timestamp: SystemTime,

    pub last_token_refresh_timestamp: SystemTime,

    pub modified_timestamp: SystemTime,
}
