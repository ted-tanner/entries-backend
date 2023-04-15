use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::schema::user_deletion_requests;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = user_deletion_requests)]
pub struct UserDeletionRequest {
    pub id: Uuid,
    pub user_id: Uuid,
    pub deletion_request_time: SystemTime,
    pub ready_for_deletion_time: SystemTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = user_deletion_requests)]
pub struct NewUserDeletionRequest {
    pub id: Uuid,
    pub user_id: Uuid,
    pub deletion_request_time: SystemTime,
    pub ready_for_deletion_time: SystemTime,
}
