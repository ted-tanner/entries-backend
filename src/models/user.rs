use chrono::{NaiveDate, NaiveDateTime};
use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};

use crate::schema::users;

#[derive(Clone, Debug, Serialize, Deserialize, Associations, Identifiable, Queryable)]
#[table_name = "users"]
pub struct User {
    pub id: uuid::Uuid,
    pub password_hash: String,
    pub is_active: bool,

    pub is_premium: bool,
    pub premium_expiration: Option<NaiveDate>,

    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub date_of_birth: NaiveDate,
    pub currency: String,

    pub modified_timestamp: NaiveDateTime,
    pub created_timestamp: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub id: uuid::Uuid,
    pub password_hash: &'a str,
    pub is_active: bool,

    pub is_premium: bool,
    pub premium_expiration: Option<NaiveDate>,

    pub email: &'a str,
    pub first_name: &'a str,
    pub last_name: &'a str,
    pub date_of_birth: NaiveDate,
    pub currency: &'a str,

    pub modified_timestamp: NaiveDateTime,
    pub created_timestamp: NaiveDateTime,
}
