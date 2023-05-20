use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};

use crate::schema::signin_nonces;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = signin_nonces, primary_key(user_email))]
pub struct SigninNonce {
    pub user_email: String,
    pub nonce: i32,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = signin_nonces, primary_key(user_email))]
pub struct NewSigninNonce<'a> {
    pub user_email: &'a str,
    pub nonce: i32,
}
