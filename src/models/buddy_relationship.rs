use chrono::NaiveDateTime;
use diesel::{Insertable, Queryable};

use serde::{Deserialize, Serialize};

use crate::models::user::User;
use crate::schema::buddy_relationships;

#[derive(Debug, Serialize, Deserialize, Identifiable, Associations, Queryable)]
#[belongs_to(User, foreign_key = "user1_id")]
// Diesel does not support multiple foreign keys to a single table
// #[belongs_to(User, foreign_key = "user2_id")] 
#[table_name = "buddy_relationships"]
pub struct BuddyRelationship {
    pub id: i32,
    pub created_timestamp: NaiveDateTime,
    pub user1_id: uuid::Uuid,
    pub user2_id: uuid::Uuid,
}

#[derive(Debug, Insertable)]
#[table_name = "buddy_relationships"]
pub struct NewBuddyRelationship {
    pub created_timestamp: NaiveDateTime,
    pub user1_id: uuid::Uuid,
    pub user2_id: uuid::Uuid,
}
