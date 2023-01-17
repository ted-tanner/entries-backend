use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
use std::time::SystemTime;
use uuid::Uuid;

use crate::db::{DaoError, DbThreadPool};
use crate::models::tombstone::NewTombstone;
use crate::schema::tombstones as tombstone_fields;
use crate::schema::tombstones::dsl::tombstones;

pub struct Dao {
    db_thread_pool: DbThreadPool,
}

impl Dao {
    pub fn new(db_thread_pool: &DbThreadPool) -> Self {
        Self {
            db_thread_pool: db_thread_pool.clone(),
        }
    }

    pub fn create_tombstone(
        &mut self,
        item_id: Uuid,
        related_user_id: Uuid,
        origin_table: &str,
    ) -> Result<usize, DaoError> {
        let new_tombstone = NewTombstone {
            item_id,
            related_user_id,
            origin_table,
            deletion_timestamp: SystemTime::now(),
        };

        Ok(dsl::insert_into(tombstones)
            .values(&new_tombstone)
            .execute(&mut self.db_thread_pool.get()?)?)
    }

    pub fn check_tombstone_exists(
        &mut self,
        item_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, DaoError> {
        Ok(dsl::select(dsl::exists(
            tombstones
                .filter(tombstone_fields::related_user_id.eq(user_id))
                .find(item_id),
        ))
        .get_result(&mut self.db_thread_pool.get()?)?)
    }
}
