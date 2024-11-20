use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::user::User;
use crate::schema::user_keystores;

#[derive(Debug, Serialize, Deserialize, Identifiable, Associations, Queryable, QueryableByName)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = user_keystores, primary_key(user_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UserKeystore {
    pub user_id: Uuid,
    pub encrypted_blob: Vec<u8>,
    pub version_nonce: i64,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = user_keystores, primary_key(user_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewUserKeystore<'a> {
    pub user_id: Uuid,
    pub encrypted_blob: &'a [u8],
    pub version_nonce: i64,
}
