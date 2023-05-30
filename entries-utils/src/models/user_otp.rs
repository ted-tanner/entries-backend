use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::schema::user_otps;

#[derive(Clone, Debug, Serialize, Deserialize, Identifiable, Queryable)]
#[diesel(table_name = user_otps, primary_key(user_email, otp))]
pub struct UserOtp {
    pub user_email: String,
    pub otp: String,
    pub expiration: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = user_otps, primary_key(user_email, otp))]
pub struct NewUserOtp<'a> {
    pub user_email: &'a str,
    pub otp: &'a str,
    pub expiration: SystemTime,
}
