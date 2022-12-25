use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::schema::users;

#[derive(Clone, Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = users)]
pub struct User {
    pub id: uuid::Uuid,
    pub password_hash: String,

    pub is_premium: bool,
    pub premium_expiration: Option<SystemTime>,

    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub date_of_birth: SystemTime,
    pub currency: String,

    pub modified_timestamp: SystemTime,
    pub created_timestamp: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    pub id: uuid::Uuid,
    pub password_hash: &'a str,

    pub is_premium: bool,
    pub premium_expiration: Option<SystemTime>,

    pub email: &'a str,
    pub first_name: &'a str,
    pub last_name: &'a str,
    pub date_of_birth: SystemTime,
    pub currency: &'a str,

    pub modified_timestamp: SystemTime,
    pub created_timestamp: SystemTime,
}
