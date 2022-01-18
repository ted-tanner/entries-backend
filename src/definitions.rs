use diesel::pg::PgConnection;
use diesel::r2d2::{self, ConnectionManager, PooledConnection};

pub type DbThreadPool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type RedisThreadPool =
    deadpool_redis::Pool;

pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;
pub type RedisConnection = deadpool_redis::Connection;
