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
#[diesel(table_name = buddy_relationships, primary_key(user1_id, user2_id))]
pub struct BuddyRelationship {
    pub user1_id: Uuid,
    pub user2_id: Uuid,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = buddy_relationships, primary_key(user1_id, user2_id))]
pub struct NewBuddyRelationship {
    pub user1_id: Uuid,
    pub user2_id: Uuid,
}
