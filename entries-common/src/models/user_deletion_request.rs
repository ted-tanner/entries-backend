use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::schema::user_deletion_requests;

#[derive(Debug, Serialize, Deserialize, Identifiable, Insertable, Queryable, QueryableByName)]
#[diesel(table_name = user_deletion_requests, primary_key(user_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UserDeletionRequest {
    pub user_id: Uuid,
    pub ready_for_deletion_time: SystemTime,
}

pub type NewUserDeletionRequest = UserDeletionRequest;
