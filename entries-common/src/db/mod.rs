use diesel_async::pooled_connection::bb8::Pool as AsyncPool;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::AsyncPgConnection;
use std::fmt;

pub mod auth;
pub mod container;
pub mod job_registry;
pub mod user;

pub type DbAsyncPool = AsyncPool<AsyncPgConnection>;
pub type DbAsyncConnection =
    bb8::PooledConnection<'static, AsyncDieselConnectionManager<AsyncPgConnection>>;

pub async fn create_db_async_pool(database_uri: &str, max_db_connections: u32) -> DbAsyncPool {
    let config = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_uri);
    AsyncPool::builder()
        .max_size(max_db_connections)
        .build(config)
        .await
        .expect("Failed to create async DB pool")
}

#[derive(Debug)]
pub enum DaoError {
    DbAsyncPoolFailure(String),
    QueryFailure(diesel::result::Error),
    OutOfDate,
    CannotRunQuery(&'static str),
    WontRunQuery, // This error indicates that the DAO refuses to run a query
}

impl std::error::Error for DaoError {}

impl fmt::Display for DaoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaoError::DbAsyncPoolFailure(e) => {
                write!(f, "DaoError: Failed to obtain async DB connection: {e}")
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

impl<E: std::error::Error + Send + Sync + 'static> From<bb8::RunError<E>> for DaoError {
    fn from(error: bb8::RunError<E>) -> Self {
        DaoError::DbAsyncPoolFailure(error.to_string())
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
    use std::time::SystemTime;
    use uuid::Uuid;

    use diesel::{dsl, QueryDsl};

    use crate::db::{create_db_async_pool, DbAsyncConnection, DbAsyncPool};

    use super::user;
    use crate::models::container::NewContainer;
    use crate::models::container_access_key::NewContainerAccessKey;
    use crate::schema::container_access_keys::dsl::container_access_keys;
    use crate::schema::containers::dsl::containers;
    use crate::schema::users::dsl::users;
    use crate::threadrand::SecureRng;

    const DB_USERNAME_VAR: &str = "ENTRIES_DB_USERNAME";
    const DB_PASSWORD_VAR: &str = "ENTRIES_DB_PASSWORD";
    const DB_HOSTNAME_VAR: &str = "ENTRIES_DB_HOSTNAME";
    const DB_PORT_VAR: &str = "ENTRIES_DB_PORT";
    const DB_NAME_VAR: &str = "ENTRIES_DB_NAME";
    const DB_MAX_CONNECTIONS_VAR: &str = "ENTRIES_DB_MAX_CONNECTIONS";

    pub static DB_ASYNC_POOL: Lazy<DbAsyncPool> = Lazy::new(|| {
        let username = env_or_panic(DB_USERNAME_VAR);
        let password = env_or_panic(DB_PASSWORD_VAR);
        let hostname = env_or_panic(DB_HOSTNAME_VAR);
        let port = env_or_panic(DB_PORT_VAR);
        let db_name = env_or_panic(DB_NAME_VAR);

        let max_connections = env_or_parse(DB_MAX_CONNECTIONS_VAR, 48u32);

        let db_uri = format!(
            "postgres://{}:{}@{}:{}/{}",
            username, password, hostname, port, db_name
        );

        // Use futures::executor::block_on which works within async contexts
        futures::executor::block_on(create_db_async_pool(&db_uri, max_connections))
    });

    pub fn db_async_pool() -> &'static DbAsyncPool {
        &DB_ASYNC_POOL
    }

    pub async fn db_async_conn() -> DbAsyncConnection {
        DB_ASYNC_POOL
            .get()
            .await
            .expect("Failed to obtain pooled DB connection for tests")
    }

    pub fn random_bytes(count: usize) -> Vec<u8> {
        (0..count).map(|_| SecureRng::next_u8()).collect()
    }

    pub fn unique_email() -> String {
        format!("db-test-{}@entries.test", SecureRng::next_u128())
    }

    pub async fn insert_container(conn: &mut DbAsyncConnection) -> Uuid {
        let container_id = Uuid::now_v7();
        let encrypted_blob = random_bytes(32);

        let new_container = NewContainer {
            id: container_id,
            encrypted_blob: &encrypted_blob,
            version_nonce: SecureRng::next_i64(),
            modified_timestamp: SystemTime::now(),
        };

        diesel_async::RunQueryDsl::execute(
            dsl::insert_into(containers).values(&new_container),
            conn,
        )
        .await
        .expect("Failed to insert container");

        container_id
    }

    pub async fn insert_container_access_key(
        conn: &mut DbAsyncConnection,
        container_id: Uuid,
        key_id: Uuid,
    ) {
        let public_key = random_bytes(32);
        let new_key = NewContainerAccessKey {
            key_id,
            container_id,
            public_key: &public_key,
            read_only: false,
        };

        diesel_async::RunQueryDsl::execute(
            dsl::insert_into(container_access_keys).values(&new_key),
            conn,
        )
        .await
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
                auth_string_hash: "test_auth_hash".to_string(),
                auth_string_hash_salt: random_bytes(16),
                auth_string_hash_mem_cost_kib: 1000,
                auth_string_hash_threads: 2,
                auth_string_hash_iterations: 2,
                password_encryption_key_salt: random_bytes(16),
                password_encryption_key_mem_cost_kib: 1000,
                password_encryption_key_threads: 2,
                password_encryption_key_iterations: 2,
                recovery_key_hash_salt_for_encryption: random_bytes(16),
                recovery_key_hash_salt_for_recovery_auth: random_bytes(16),
                recovery_key_hash_mem_cost_kib: 1000,
                recovery_key_hash_threads: 2,
                recovery_key_hash_iterations: 2,
                recovery_key_auth_hash_rehashed_with_auth_string_params: "test_recovery_hash"
                    .to_string(),
                encryption_key_encrypted_with_password: random_bytes(32),
                encryption_key_encrypted_with_recovery_key: random_bytes(32),
                public_key_id: Uuid::now_v7(),
                public_key: random_bytes(32),
                preferences_encrypted: random_bytes(32),
                preferences_version_nonce: SecureRng::next_i64(),
                user_keystore_encrypted: random_bytes(32),
                user_keystore_version_nonce: SecureRng::next_i64(),
            }
        }

        pub async fn insert(&self, user_dao: &user::Dao) -> Uuid {
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
                .await
                .expect("Failed to create test user")
        }
    }

    pub struct InsertedTestUser {
        pub id: Uuid,
        pub data: TestUserData,
    }

    pub async fn create_user_with_dao(user_dao: &user::Dao) -> InsertedTestUser {
        let data = TestUserData::random();
        let id = data.insert(user_dao).await;
        InsertedTestUser { id, data }
    }

    pub async fn delete_user(user_id: Uuid) {
        if let Ok(mut conn) = db_async_pool().get().await {
            let _ =
                diesel_async::RunQueryDsl::execute(diesel::delete(users.find(user_id)), &mut conn)
                    .await;
        }
    }

    fn env_or_panic(key: &str) -> String {
        std::env::var(key).unwrap_or_else(|_| panic!("Environment variable {key} must be set"))
    }

    fn env_or_parse<T>(key: &str, default: T) -> T
    where
        T: std::str::FromStr,
    {
        std::env::var(key)
            .ok()
            .and_then(|val| val.parse().ok())
            .unwrap_or(default)
    }
}
