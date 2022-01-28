use diesel::pg::PgConnection;
use diesel::r2d2::{self, ConnectionManager, PooledConnection};
use std::sync::{Arc, Mutex};

pub type DbThreadPool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type RedisClient = redis::Client;

pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;
pub type RedisAsyncConnection = redis::aio::Connection;
pub type RedisSyncConnection = redis::Connection;

pub type AtomicMutex<T> = Arc<Mutex<T>>;
