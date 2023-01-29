use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
use std::time::SystemTime;
use uuid::Uuid;

use crate::db::{DaoError, DbThreadPool};
use crate::models::tombstone::{NewTombstone, Tombstone};
use crate::request_io::OutputTombstone;
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

    pub fn check_tombstone_exists(
        &mut self,
        item_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, DaoError> {
        Ok(dsl::select(dsl::exists(
            tombstones
                .find(item_id)
                .filter(tombstone_fields::related_user_id.eq(user_id)),
        ))
        .get_result(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_tombstones_since(
        &mut self,
        from_time: SystemTime,
        user_id: Uuid,
    ) -> Result<Vec<OutputTombstone>, DaoError> {
        Ok(tombstones
            .select((
                tombstone_fields::item_id,
                tombstone_fields::origin_table,
                tombstone_fields::deletion_timestamp,
            ))
            .filter(tombstone_fields::related_user_id.eq(user_id))
            .filter(tombstone_fields::deletion_timestamp.gt(from_time))
            .get_results::<OutputTombstone>(&mut self.db_thread_pool.get()?)?)
    }
}
