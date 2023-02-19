use diesel::{Insertable, Queryable, QueryableByName};
use serde::{Deserialize, Serialize};

use uuid::Uuid;

use crate::schema::buddy_requests;

#[derive(Debug, Serialize, Deserialize, Identifiable, Queryable, QueryableByName)]
#[diesel(table_name = buddy_requests)]
pub struct BuddyRequest {
    pub id: Uuid,

    pub recipient_user_email: String,
    pub sender_user_email: String,

    pub sender_name_encrypted: Option<String>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = buddy_requests)]
pub struct NewBuddyRequest<'a> {
    pub id: Uuid,

    pub recipient_user_email: &'a str,
    pub sender_user_email: &'a str,

    pub sender_name_encrypted: Option<&'a str>,
}
