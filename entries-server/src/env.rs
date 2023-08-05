use aes_gcm::{aead::KeyInit, Aes128Gcm};
use base64::engine::general_purpose::STANDARD as b64;
use base64::Engine;
use lettre::message::Mailbox;
use once_cell::sync::Lazy;
use std::cell::UnsafeCell;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

pub static CONF: Lazy<Config> = Lazy::new(|| Config::from_env().expect("Failed to load config"));

const DB_USERNAME_VAR: &str = "ENTRIES_DB_USERNAME";
const DB_PASSWORD_VAR: &str = "ENTRIES_DB_PASSWORD";
const DB_HOSTNAME_VAR: &str = "ENTRIES_DB_HOSTNAME";
const DB_PORT_VAR: &str = "ENTRIES_DB_PORT";
const DB_NAME_VAR: &str = "ENTRIES_DB_NAME";
const DB_MAX_CONNECTIONS_VAR: &str = "ENTRIES_DB_MAX_CONNECTIONS";
const DB_IDLE_TIMEOUT_SECS_VAR: &str = "ENTRIES_DB_IDLE_TIMEOUT_SECS";

const HASHING_KEY_VAR: &str = "ENTRIES_HASHING_KEY_B64";
const TOKEN_SIGNING_KEY_VAR: &str = "ENTRIES_TOKEN_SIGNING_KEY_B64";
const AMAZON_SES_USERNAME_VAR: &str = "ENTRIES_AMAZON_SES_USERNAME";
const AMAZON_SES_KEY_VAR: &str = "ENTRIES_AMAZON_SES_KEY";
const TOKEN_ENCRYPTION_KEY_VAR: &str = "ENTRIES_TOKEN_ENCRYPTION_KEY_B64";

const HASH_LENGTH_VAR: &str = "ENTRIES_HASH_LENGTH";
const HASH_ITERATIONS_VAR: &str = "ENTRIES_HASH_ITERATIONS";
const HASH_MEM_COST_KIB_VAR: &str = "ENTRIES_HASH_MEM_COST_KIB";
const HASH_THREADS_VAR: &str = "ENTRIES_HASH_THREADS";
const HASH_SALT_LENGTH_VAR: &str = "ENTRIES_HASH_SALT_LENGTH";

const EMAIL_ENABLED_VAR: &str = "ENTRIES_EMAIL_ENABLED";
const EMAIL_FROM_ADDR: &str = "ENTRIES_EMAIL_FROM_ADDR";
const EMAIL_REPLY_TO_ADDR: &str = "ENTRIES_EMAIL_REPLY_TO_ADDR";
const SMTP_ADDRESS_VAR: &str = "ENTRIES_SMTP_ADDRESS";
const MAX_SMTP_CONNECTIONS_VAR: &str = "ENTRIES_MAX_SMTP_CONNECTIONS";
const SMTP_IDLE_TIMEOUT_SECS_VAR: &str = "ENTRIES_SMTP_IDLE_TIMEOUT_SECS";

const USER_VERIFICATION_URL_VAR: &str = "ENTRIES_USER_VERIFICATION_URL";
const USER_DELETION_URL_VAR: &str = "ENTRIES_USER_DELETION_URL";

const ACCESS_TOKEN_LIFETIME_MINS_VAR: &str = "ENTRIES_ACCESS_TOKEN_LIFETIME_MINS";
const REFRESH_TOKEN_LIFETIME_DAYS_VAR: &str = "ENTRIES_REFRESH_TOKEN_LIFETIME_DAYS";
const SIGNIN_TOKEN_LIFETIME_MINS_VAR: &str = "ENTRIES_SIGNIN_TOKEN_LIFETIME_MINS";
const USER_CREATION_TOKEN_LIFETIME_DAYS_VAR: &str = "ENTRIES_USER_CREATION_TOKEN_LIFETIME_DAYS";
const USER_DELETION_TOKEN_LIFETIME_DAYS_VAR: &str = "ENTRIES_USER_DELETION_TOKEN_LIFETIME_DAYS";
const OTP_LIFETIME_MINS_VAR: &str = "ENTRIES_OTP_LIFETIME_MINS";

const ACTIX_WORKER_COUNT_VAR: &str = "ENTRIES_ACTIX_WORKER_COUNT";

const LOG_LEVEL_VAR: &str = "ENTRIES_LOG_LEVEL";
const USER_DELETION_DELAY_DAYS_VAR: &str = "ENTRIES_USER_DELETION_DELAY_DAYS";

const HASHING_KEY_SIZE: usize = 32;
const TOKEN_SIGNING_KEY_SIZE: usize = 64;
const TOKEN_ENCRYPTION_KEY_SIZE: usize = 16;

#[derive(Zeroize)]
pub struct ConfigInner {
    pub db_username: String,
    pub db_password: String,
    pub db_hostname: String,
    pub db_port: u16,
    pub db_name: String,
    #[zeroize(skip)]
    pub db_max_connections: u32,
    #[zeroize(skip)]
    pub db_idle_timeout_secs: Duration,

    pub hashing_key: [u8; HASHING_KEY_SIZE],
    pub token_signing_key: [u8; TOKEN_SIGNING_KEY_SIZE],
    pub amazon_ses_username: String,
    pub amazon_ses_key: String,
    #[zeroize(skip)]
    pub token_encryption_cipher: Aes128Gcm,

    pub hash_length: u32,
    pub hash_iterations: u32,
    pub hash_mem_cost_kib: u32,
    pub hash_threads: u32,
    pub hash_salt_length: u32,

    pub email_enabled: bool,
    #[zeroize(skip)]
    pub email_from_address: Mailbox,
    #[zeroize(skip)]
    pub email_reply_to_address: Mailbox,
    pub smtp_address: String,
    #[zeroize(skip)]
    pub max_smtp_connections: u32,
    #[zeroize(skip)]
    pub smtp_idle_timeout_secs: Duration,

    #[zeroize(skip)]
    pub user_verification_url: String,
    #[zeroize(skip)]
    pub user_deletion_url: String,

    #[zeroize(skip)]
    pub access_token_lifetime: Duration,
    #[zeroize(skip)]
    pub refresh_token_lifetime: Duration,
    #[zeroize(skip)]
    pub signin_token_lifetime: Duration,
    #[zeroize(skip)]
    pub user_creation_token_lifetime: Duration,
    #[zeroize(skip)]
    pub user_deletion_token_lifetime: Duration,
    #[zeroize(skip)]
    pub otp_lifetime: Duration,

    #[zeroize(skip)]
    pub actix_worker_count: usize,

    #[zeroize(skip)]
    pub log_level: String,
    #[zeroize(skip)]
    pub user_deletion_delay_days: u64,
}

pub struct Config {
    inner: UnsafeCell<ConfigInner>,
}

impl Deref for Config {
    type Target = ConfigInner;

    fn deref(&self) -> &Self::Target {
        // Safe as long as `unsafe Config::zeroize()` hasn't been called
        unsafe { &*self.inner.get() }
    }
}

// Safe to be shared across threads as long as `unsafe Config::zeroize()` hasn't been called
unsafe impl Sync for Config {}

impl Config {
    pub fn from_env() -> Result<Config, ConfigError> {
        let hashing_key = Zeroizing::new(
            b64.decode(env_var::<String>(HASHING_KEY_VAR)?.as_bytes())
                .map_err(|_| ConfigError::InvalidVar(HASHING_KEY_VAR))?,
        );
        let hashing_key = hashing_key[..HASHING_KEY_SIZE]
            .try_into()
            .map_err(|_| ConfigError::InvalidVar(HASHING_KEY_VAR))?;

        let token_signing_key = Zeroizing::new(
            b64.decode(env_var::<String>(TOKEN_SIGNING_KEY_VAR)?.as_bytes())
                .map_err(|_| ConfigError::InvalidVar(TOKEN_SIGNING_KEY_VAR))?,
        );
        let token_signing_key = token_signing_key[..TOKEN_SIGNING_KEY_SIZE]
            .try_into()
            .map_err(|_| ConfigError::InvalidVar(TOKEN_SIGNING_KEY_VAR))?;

        let token_encryption_key = Zeroizing::new(
            b64.decode(env_var::<String>(TOKEN_ENCRYPTION_KEY_VAR)?.as_bytes())
                .map_err(|_| ConfigError::InvalidVar(TOKEN_ENCRYPTION_KEY_VAR))?,
        );

        let cipher = Aes128Gcm::new(
            token_encryption_key[..TOKEN_ENCRYPTION_KEY_SIZE]
                .try_into()
                .map_err(|_| ConfigError::InvalidVar(TOKEN_ENCRYPTION_KEY_VAR))?,
        );

        let email_from_address: Mailbox = env_var::<String>(EMAIL_FROM_ADDR)?
            .parse()
            .map_err(|_| ConfigError::InvalidVar(EMAIL_FROM_ADDR))?;
        let email_reply_to_address: Mailbox = env_var::<String>(EMAIL_REPLY_TO_ADDR)?
            .parse()
            .map_err(|_| ConfigError::InvalidVar(EMAIL_REPLY_TO_ADDR))?;

        let inner = ConfigInner {
            db_username: env_var(DB_USERNAME_VAR)?,
            db_password: env_var(DB_PASSWORD_VAR)?,
            db_hostname: env_var(DB_HOSTNAME_VAR)?,
            db_port: env_var(DB_PORT_VAR)?,
            db_name: env_var(DB_NAME_VAR)?,
            db_max_connections: env_var_or(DB_MAX_CONNECTIONS_VAR, 48),
            db_idle_timeout_secs: Duration::from_secs(env_var_or(DB_IDLE_TIMEOUT_SECS_VAR, 30)),

            hashing_key,
            token_signing_key,
            amazon_ses_username: env_var(AMAZON_SES_USERNAME_VAR)?,
            amazon_ses_key: env_var(AMAZON_SES_KEY_VAR)?,
            token_encryption_cipher: cipher,

            hash_length: env_var(HASH_LENGTH_VAR)?,
            hash_iterations: env_var(HASH_ITERATIONS_VAR)?,
            hash_mem_cost_kib: env_var(HASH_MEM_COST_KIB_VAR)?,
            hash_threads: env_var(HASH_THREADS_VAR)?,
            hash_salt_length: env_var(HASH_SALT_LENGTH_VAR)?,

            email_enabled: if cfg!(test) {
                false
            } else {
                env_var(EMAIL_ENABLED_VAR)?
            },
            email_from_address,
            email_reply_to_address,
            smtp_address: env_var(SMTP_ADDRESS_VAR)?,
            max_smtp_connections: env_var_or(MAX_SMTP_CONNECTIONS_VAR, 24),
            smtp_idle_timeout_secs: Duration::from_secs(env_var_or(SMTP_IDLE_TIMEOUT_SECS_VAR, 60)),

            user_verification_url: env_var(USER_VERIFICATION_URL_VAR)?,
            user_deletion_url: env_var(USER_DELETION_URL_VAR)?,

            access_token_lifetime: Duration::from_secs(
                env_var_or(ACCESS_TOKEN_LIFETIME_MINS_VAR, 15) * 60,
            ),
            refresh_token_lifetime: Duration::from_secs(
                env_var_or(REFRESH_TOKEN_LIFETIME_DAYS_VAR, 30) * 86400,
            ),
            signin_token_lifetime: Duration::from_secs(
                env_var_or(SIGNIN_TOKEN_LIFETIME_MINS_VAR, 30) * 60,
            ),
            user_creation_token_lifetime: Duration::from_secs(
                env_var_or(USER_CREATION_TOKEN_LIFETIME_DAYS_VAR, 7) * 86400,
            ),
            user_deletion_token_lifetime: Duration::from_secs(
                env_var_or(USER_DELETION_TOKEN_LIFETIME_DAYS_VAR, 7) * 86400,
            ),
            otp_lifetime: Duration::from_secs(env_var_or(OTP_LIFETIME_MINS_VAR, 15) * 60),

            actix_worker_count: env_var_or(ACTIX_WORKER_COUNT_VAR, num_cpus::get()),

            log_level: env_var_or(LOG_LEVEL_VAR, String::from("info")),
            user_deletion_delay_days: env_var_or(USER_DELETION_DELAY_DAYS_VAR, 7),
        };

        Ok(Config {
            inner: UnsafeCell::new(inner),
        })
    }

    /// # Safety
    ///
    /// Safe only if the Config isn't being used by other threads or across an async
    /// boundary. Generally, this should only be used at the end of the main function once
    /// all threads have been joined.
    pub unsafe fn zeroize(&self) {
        unsafe {
            (*self.inner.get()).zeroize();
        }
    }
}

fn env_var<T: FromStr>(key: &'static str) -> Result<T, ConfigError> {
    let var = std::env::var(key).map_err(|_| ConfigError::missing(key))?;
    let var: T = var.parse().map_err(|_| ConfigError::invalid(key))?;
    Ok(var)
}

fn env_var_or<T: FromStr>(key: &'static str, default: T) -> T {
    let Ok(var) = std::env::var(key) else {
        return default;
    };

    var.parse().unwrap_or(default)
}

#[derive(Clone, Copy, Debug)]
pub enum ConfigError {
    MissingVar(&'static str),
    InvalidVar(&'static str),
}

impl ConfigError {
    fn missing(var_name: &'static str) -> Self {
        Self::MissingVar(var_name)
    }

    fn invalid(var_name: &'static str) -> Self {
        Self::InvalidVar(var_name)
    }
}

impl std::error::Error for ConfigError {}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVar(key) => write!(f, "Missing environment variable '{}'", key),
            Self::InvalidVar(key) => write!(f, "Environment variable '{}' is invalid", key),
        }
    }
}

#[cfg(test)]
pub mod testing {
    use entries_utils::db::{create_db_thread_pool, DbThreadPool};
    use entries_utils::email::senders::MockSender;
    use entries_utils::email::SendEmail;

    use std::sync::Arc;

    use super::*;

    pub static DB_THREAD_POOL: Lazy<DbThreadPool> = Lazy::new(|| {
        create_db_thread_pool(
            &format!(
                "postgres://{}:{}@{}:{}/{}",
                CONF.db_username, CONF.db_password, CONF.db_hostname, CONF.db_port, CONF.db_name,
            ),
            Some(CONF.db_max_connections),
        )
    });

    pub static SMTP_THREAD_POOL: Lazy<Arc<Box<dyn SendEmail>>> =
        Lazy::new(|| Arc::new(Box::new(MockSender::new())));
}
