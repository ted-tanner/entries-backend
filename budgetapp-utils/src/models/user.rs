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

    pub created_timestamp: SystemTime,

    pub public_key: Vec<u8>,

    pub last_token_refresh_timestamp: SystemTime,
    pub last_token_refresh_request_app_version: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    pub id: Uuid,
    pub email: &'a str,
    pub is_verified: bool,

    pub created_timestamp: SystemTime,

    pub public_key: &'a [u8],

    pub last_token_refresh_timestamp: SystemTime,
    pub last_token_refresh_request_app_version: &'a str,
}
