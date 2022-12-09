use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, PooledConnection};
use std::fmt;

pub mod auth;
pub mod budget;
pub mod user;

pub type DbThreadPool = diesel::r2d2::Pool<ConnectionManager<PgConnection>>;
pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

pub fn create_db_thread_pool(database_uri: &str, max_db_connections: Option<u32>) -> DbThreadPool {
    r2d2::Pool::builder()
        .max_size(max_db_connections.unwrap_or_else(|| {
            (num_cpus::get() * 2)
                .try_into()
                .expect("Unable to obtain system CPU count")
        }))
        .build(ConnectionManager::<PgConnection>::new(database_uri))
        .expect("Failed to create DB thread pool")
}

#[derive(Debug)]
pub enum DaoError {
    DbThreadPoolFailure(r2d2::Error),
    QueryFailure(diesel::result::Error),
}

impl std::error::Error for DaoError {}

impl fmt::Display for DaoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaoError::DbThreadPoolFailure(e) => {
                write!(f, "DaoError: Failed to obtain DB connection: {}", e)
            }
            DaoError::QueryFailure(e) => {
                write!(f, "DaoError: Query failed: {}", e)
            }
        }
    }
}

impl From<r2d2::Error> for DaoError {
    fn from(error: r2d2::Error) -> Self {
        DaoError::DbThreadPoolFailure(error)
    }
}

impl From<diesel::result::Error> for DaoError {
    fn from(error: diesel::result::Error) -> Self {
        DaoError::QueryFailure(error)
    }
}
