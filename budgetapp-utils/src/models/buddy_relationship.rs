use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::user::User;
use crate::schema::buddy_relationships;

#[derive(Debug, Serialize, Deserialize, Identifiable, Associations, Queryable)]
#[diesel(belongs_to(User, foreign_key = user1_id))]
// Diesel does not support multiple foreign keys to a single table
// #[diesel(belongs_to(User, foreign_key = user2_id))]
#[diesel(table_name = buddy_relationships)]
pub struct BuddyRelationship {
    pub id: i32,
    pub created_timestamp: SystemTime,
    pub user1_id: Uuid,
    pub user2_id: Uuid,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = buddy_relationships)]
pub struct NewBuddyRelationship {
    pub created_timestamp: SystemTime,
    pub user1_id: Uuid,
    pub user2_id: Uuid,
}
