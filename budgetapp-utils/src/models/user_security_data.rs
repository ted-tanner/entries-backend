use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::schema::user_security_data;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = user_security_data, primary_key(user_id))]
pub struct UserSecurityData {
    pub user_id: Uuid,

    pub auth_string_hash: String,

    pub auth_string_salt: String,
    pub auth_string_iters: i32,

    pub password_encryption_salt: String,
    pub password_encryption_iters: i32,

    pub recovery_key_salt: String,
    pub recovery_key_iters: i32,

    pub encryption_key_user_password_encrypted: String,
    pub encryption_key_recovery_key_encrypted: String,

    pub public_rsa_key: String,
    pub public_rsa_key_created_timestamp: String,

    pub last_token_refresh_timestamp: SystemTime,
    
    pub modified_timestamp: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = user_security_data, primary_key(user_id))]
pub struct NewUserSecurityData<'a> {
    pub user_id: Uuid,
    
    pub auth_string_hash: &'a str,

    pub auth_string_salt: &'a str,
    pub auth_string_iters: i32,

    pub password_encryption_salt: &'a str,
    pub password_encryption_iters: i32,

    pub recovery_key_salt: &'a str,
    pub recovery_key_iters: i32,

    pub encryption_key_user_password_encrypted: &'a str,
    pub encryption_key_recovery_key_encrypted: &'a str,

    pub public_rsa_key: &'a str,
    pub public_rsa_key_created_timestamp: &'a str,

    pub last_token_refresh_timestamp: SystemTime,

    pub modified_timestamp: SystemTime,
}
