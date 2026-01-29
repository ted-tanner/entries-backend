use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::user::User;
use crate::schema::user_flags;

#[derive(Debug, Serialize, Deserialize, Identifiable, Associations, Queryable, QueryableByName)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = user_flags, primary_key(user_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UserFlags {
    pub user_id: Uuid,
    pub has_performed_bulk_upload: bool,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = user_flags, primary_key(user_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewUserFlags {
    pub user_id: Uuid,
    pub has_performed_bulk_upload: bool,
}
