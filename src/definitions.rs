use diesel::r2d2::{self, ConnectionManager};
use diesel::pg::PgConnection;

pub type ThreadPool = r2d2::Pool<ConnectionManager<PgConnection>>;