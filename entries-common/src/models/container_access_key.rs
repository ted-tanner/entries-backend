use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::container::Container;
use crate::schema::container_access_keys;

#[derive(Clone, Debug, Serialize, Deserialize, Associations, Identifiable, Queryable)]
#[diesel(belongs_to(Container, foreign_key = container_id))]
#[diesel(table_name = container_access_keys, primary_key(key_id, container_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ContainerAccessKey {
    pub key_id: Uuid,
    pub container_id: Uuid,
    pub public_key: Vec<u8>,
    pub read_only: bool,
}

#[derive(Clone, Debug, Insertable)]
#[diesel(table_name = container_access_keys, primary_key(key_id, container_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewContainerAccessKey<'a> {
    pub key_id: Uuid,
    pub container_id: Uuid,
    pub public_key: &'a [u8],
    pub read_only: bool,
}
