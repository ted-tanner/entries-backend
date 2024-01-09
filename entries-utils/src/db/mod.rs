use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, PooledConnection};
use std::fmt;
use std::time::Duration;

pub mod auth;
pub mod budget;
pub mod job_registry;
pub mod user;

pub type DbThreadPool = diesel::r2d2::Pool<ConnectionManager<PgConnection>>;
pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

pub fn create_db_thread_pool(
    database_uri: &str,
    max_db_connections: u32,
    idle_timeout: Duration,
) -> DbThreadPool {
    r2d2::Pool::builder()
        .max_size(max_db_connections)
        .idle_timeout(Some(idle_timeout))
        .build(ConnectionManager::<PgConnection>::new(database_uri))
        .expect("Failed to create DB thread pool")
}

#[derive(Debug)]
pub enum DaoError {
    DbThreadPoolFailure(r2d2::Error),
    QueryFailure(diesel::result::Error),
    OutOfDateHash,
    CannotRunQuery(&'static str),
    WontRunQuery, // This error indicates that the DAO refuses to run a query
}

impl std::error::Error for DaoError {}

impl fmt::Display for DaoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaoError::DbThreadPoolFailure(e) => {
                write!(f, "DaoError: Failed to obtain DB connection: {e}")
            }
            DaoError::QueryFailure(e) => {
                write!(f, "DaoError: Query failed: {e}")
            }
            DaoError::OutOfDateHash => {
                write!(f, "DaoError: Hash was out of date")
            }
            DaoError::CannotRunQuery(msg) => {
                write!(f, "DaoError: Cannot run query: {msg}")
            }
            DaoError::WontRunQuery => {
                write!(f, "DaoError: DAO will not run query")
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
