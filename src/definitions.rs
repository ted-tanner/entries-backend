use diesel::pg::PgConnection;
use diesel::r2d2::{self, ConnectionManager, PooledConnection};
use std::sync::{Arc, Mutex};

pub type DbThreadPool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

pub type AtomicMutex<T> = Arc<Mutex<T>>;
