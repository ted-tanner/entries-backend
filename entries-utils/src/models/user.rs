use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::schema::users;

#[derive(Clone, Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub is_verified: bool,

    pub public_key: Vec<u8>,

    pub created_timestamp: SystemTime,

    pub auth_string_hash: String,

    pub auth_string_salt: Vec<u8>,
    pub auth_string_memory_cost_kib: i32,
    pub auth_string_parallelism_factor: i32,
    pub auth_string_iters: i32,

    pub password_encryption_salt: Vec<u8>,
    pub password_encryption_memory_cost_kib: i32,
    pub password_encryption_parallelism_factor: i32,
    pub password_encryption_iters: i32,

    pub recovery_key_salt: Vec<u8>,
    pub recovery_key_memory_cost_kib: i32,
    pub recovery_key_parallelism_factor: i32,
    pub recovery_key_iters: i32,

    pub encryption_key_encrypted_with_password: Vec<u8>,
    pub encryption_key_encrypted_with_recovery_key: Vec<u8>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    pub id: Uuid,
    pub email: &'a str,
    pub is_verified: bool,

    pub public_key: &'a [u8],

    pub created_timestamp: SystemTime,

    pub auth_string_hash: &'a str,

    pub auth_string_salt: &'a [u8],
    pub auth_string_memory_cost_kib: i32,
    pub auth_string_parallelism_factor: i32,
    pub auth_string_iters: i32,

    pub password_encryption_salt: &'a [u8],
    pub password_encryption_memory_cost_kib: i32,
    pub password_encryption_parallelism_factor: i32,
    pub password_encryption_iters: i32,

    pub recovery_key_salt: &'a [u8],
    pub recovery_key_memory_cost_kib: i32,
    pub recovery_key_parallelism_factor: i32,
    pub recovery_key_iters: i32,

    pub encryption_key_encrypted_with_password: &'a [u8],
    pub encryption_key_encrypted_with_recovery_key: &'a [u8],
}
