use diesel::pg::PgConnection;
use diesel::r2d2::{self, ConnectionManager};

pub type DbThreadPool = r2d2::Pool<ConnectionManager<PgConnection>>;
