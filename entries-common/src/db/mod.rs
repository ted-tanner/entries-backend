use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, PooledConnection};
use std::fmt;
use std::time::Duration;

pub mod auth;
pub mod container;
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
    OutOfDate,
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
            DaoError::OutOfDate => {
                write!(f, "DaoError: Version nonce was out of date")
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

#[cfg(test)]
pub mod test_utils {
    use once_cell::sync::Lazy;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    use diesel::{dsl, QueryDsl, RunQueryDsl};

    use super::user;
    use crate::models::container::NewContainer;
    use crate::models::container_access_key::NewContainerAccessKey;
    use crate::schema::container_access_keys::dsl::container_access_keys;
    use crate::schema::containers::dsl::containers;
    use crate::schema::users::dsl::users;
    use crate::threadrand::SecureRng;

    use super::{create_db_thread_pool, DbConnection, DbThreadPool};

    const DB_USERNAME_VAR: &str = "ENTRIES_DB_USERNAME";
    const DB_PASSWORD_VAR: &str = "ENTRIES_DB_PASSWORD";
    const DB_HOSTNAME_VAR: &str = "ENTRIES_DB_HOSTNAME";
    const DB_PORT_VAR: &str = "ENTRIES_DB_PORT";
    const DB_NAME_VAR: &str = "ENTRIES_DB_NAME";
    const DB_MAX_CONNECTIONS_VAR: &str = "ENTRIES_DB_MAX_CONNECTIONS";
    const DB_IDLE_TIMEOUT_SECS_VAR: &str = "ENTRIES_DB_IDLE_TIMEOUT_SECS";

    pub static DB_THREAD_POOL: Lazy<DbThreadPool> = Lazy::new(|| {
        let username = env_or_panic(DB_USERNAME_VAR);
        let password = env_or_panic(DB_PASSWORD_VAR);
        let hostname = env_or_panic(DB_HOSTNAME_VAR);
        let port = env_or_panic(DB_PORT_VAR);
        let db_name = env_or_panic(DB_NAME_VAR);

        let max_connections = env_or_parse(DB_MAX_CONNECTIONS_VAR, 8u32);
        let idle_timeout_secs = env_or_parse(DB_IDLE_TIMEOUT_SECS_VAR, 30u64);

        create_db_thread_pool(
            &format!(
                "postgres://{}:{}@{}:{}/{}",
                username, password, hostname, port, db_name
            ),
            max_connections,
            Duration::from_secs(idle_timeout_secs),
        )
    });

    pub fn db_pool() -> &'static DbThreadPool {
        &DB_THREAD_POOL
    }

    pub fn db_conn() -> DbConnection {
        DB_THREAD_POOL
            .get()
            .expect("Failed to obtain pooled DB connection for tests")
    }

    pub fn random_bytes(count: usize) -> Vec<u8> {
        (0..count).map(|_| SecureRng::next_u8()).collect()
    }

    pub fn unique_email() -> String {
        format!("db-test-{}@entries.test", SecureRng::next_u128())
    }

    pub fn insert_container(conn: &mut DbConnection) -> Uuid {
        let container_id = Uuid::now_v7();
        let encrypted_blob = random_bytes(32);

        let new_container = NewContainer {
            id: container_id,
            encrypted_blob: &encrypted_blob,
            version_nonce: SecureRng::next_i64(),
            modified_timestamp: SystemTime::now(),
        };

        dsl::insert_into(containers)
            .values(&new_container)
            .execute(conn)
            .expect("Failed to insert container");

        container_id
    }

    pub fn insert_container_access_key(conn: &mut DbConnection, container_id: Uuid, key_id: Uuid) {
        let public_key = random_bytes(32);
        let new_key = NewContainerAccessKey {
            key_id,
            container_id,
            public_key: &public_key,
            read_only: false,
        };

        dsl::insert_into(container_access_keys)
            .values(&new_key)
            .execute(conn)
            .expect("Failed to insert container access key");
    }

    #[derive(Clone)]
    pub struct TestUserData {
        pub email: String,
        pub auth_string_hash: String,
        pub auth_string_hash_salt: Vec<u8>,
        pub auth_string_hash_mem_cost_kib: i32,
        pub auth_string_hash_threads: i32,
        pub auth_string_hash_iterations: i32,
        pub password_encryption_key_salt: Vec<u8>,
        pub password_encryption_key_mem_cost_kib: i32,
        pub password_encryption_key_threads: i32,
        pub password_encryption_key_iterations: i32,
        pub recovery_key_hash_salt_for_encryption: Vec<u8>,
        pub recovery_key_hash_salt_for_recovery_auth: Vec<u8>,
        pub recovery_key_hash_mem_cost_kib: i32,
        pub recovery_key_hash_threads: i32,
        pub recovery_key_hash_iterations: i32,
        pub recovery_key_auth_hash_rehashed_with_auth_string_params: String,
        pub encryption_key_encrypted_with_password: Vec<u8>,
        pub encryption_key_encrypted_with_recovery_key: Vec<u8>,
        pub public_key_id: Uuid,
        pub public_key: Vec<u8>,
        pub preferences_encrypted: Vec<u8>,
        pub preferences_version_nonce: i64,
        pub user_keystore_encrypted: Vec<u8>,
        pub user_keystore_version_nonce: i64,
    }

    impl TestUserData {
        pub fn random() -> Self {
            Self {
                email: unique_email(),
                auth_string_hash: format!("auth-hash-{}", SecureRng::next_u128()),
                auth_string_hash_salt: random_bytes(16),
                auth_string_hash_mem_cost_kib: 1024,
                auth_string_hash_threads: 1,
                auth_string_hash_iterations: 4,
                password_encryption_key_salt: random_bytes(16),
                password_encryption_key_mem_cost_kib: 1024,
                password_encryption_key_threads: 1,
                password_encryption_key_iterations: 2,
                recovery_key_hash_salt_for_encryption: random_bytes(16),
                recovery_key_hash_salt_for_recovery_auth: random_bytes(16),
                recovery_key_hash_mem_cost_kib: 1024,
                recovery_key_hash_threads: 1,
                recovery_key_hash_iterations: 2,
                recovery_key_auth_hash_rehashed_with_auth_string_params: format!(
                    "recovery-hash-{}",
                    SecureRng::next_u128()
                ),
                encryption_key_encrypted_with_password: random_bytes(24),
                encryption_key_encrypted_with_recovery_key: random_bytes(24),
                public_key_id: Uuid::now_v7(),
                public_key: random_bytes(32),
                preferences_encrypted: random_bytes(32),
                preferences_version_nonce: SecureRng::next_i64(),
                user_keystore_encrypted: random_bytes(32),
                user_keystore_version_nonce: SecureRng::next_i64(),
            }
        }

        pub fn insert(&self, user_dao: &user::Dao) -> Uuid {
            user_dao
                .create_user(
                    &self.email,
                    &self.auth_string_hash,
                    &self.auth_string_hash_salt,
                    self.auth_string_hash_mem_cost_kib,
                    self.auth_string_hash_threads,
                    self.auth_string_hash_iterations,
                    &self.password_encryption_key_salt,
                    self.password_encryption_key_mem_cost_kib,
                    self.password_encryption_key_threads,
                    self.password_encryption_key_iterations,
                    &self.recovery_key_hash_salt_for_encryption,
                    &self.recovery_key_hash_salt_for_recovery_auth,
                    self.recovery_key_hash_mem_cost_kib,
                    self.recovery_key_hash_threads,
                    self.recovery_key_hash_iterations,
                    &self.recovery_key_auth_hash_rehashed_with_auth_string_params,
                    &self.encryption_key_encrypted_with_password,
                    &self.encryption_key_encrypted_with_recovery_key,
                    self.public_key_id,
                    &self.public_key,
                    &self.preferences_encrypted,
                    self.preferences_version_nonce,
                    &self.user_keystore_encrypted,
                    self.user_keystore_version_nonce,
                )
                .expect("Failed to create test user")
        }
    }

    pub struct InsertedTestUser {
        pub id: Uuid,
        pub data: TestUserData,
    }

    pub fn create_user_with_dao(user_dao: &user::Dao) -> InsertedTestUser {
        let data = TestUserData::random();
        let user_id = data.insert(user_dao);

        InsertedTestUser { id: user_id, data }
    }

    pub fn create_user() -> InsertedTestUser {
        let dao = user::Dao::new(db_pool());
        create_user_with_dao(&dao)
    }

    pub fn delete_user(user_id: Uuid) {
        if let Ok(mut conn) = db_pool().get() {
            let _ = diesel::delete(users.find(user_id)).execute(&mut conn);
        }
    }

    fn env_or_panic(key: &str) -> String {
        std::env::var(key)
            .unwrap_or_else(|_| panic!("Missing environment variable '{key}' for DB tests"))
    }

    fn env_or_parse<T>(key: &str, default: T) -> T
    where
        T: Copy + std::str::FromStr,
        <T as std::str::FromStr>::Err: std::fmt::Debug,
    {
        match std::env::var(key) {
            Ok(value) => value
                .parse::<T>()
                .unwrap_or_else(|_| panic!("Invalid value for '{key}'")),
            Err(_) => default,
        }
    }
}
