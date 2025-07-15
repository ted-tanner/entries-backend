use once_cell::sync::Lazy;
use std::cell::UnsafeCell;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;
use std::time::Duration;
use zeroize::Zeroize;

const DB_USERNAME_VAR: &str = "ENTRIES_DB_USERNAME";
const DB_PASSWORD_VAR: &str = "ENTRIES_DB_PASSWORD";
const DB_HOSTNAME_VAR: &str = "ENTRIES_DB_HOSTNAME";
const DB_PORT_VAR: &str = "ENTRIES_DB_PORT";
const DB_NAME_VAR: &str = "ENTRIES_DB_NAME";
const DB_MAX_CONNECTIONS_VAR: &str = "ENTRIES_DB_MAX_CONNECTIONS";
const DB_IDLE_TIMEOUT_SECS_VAR: &str = "ENTRIES_DB_IDLE_TIMEOUT_SECS";

const UPDATE_FREQUENCY_MS_VAR: &str = "ENTRIES_JOB_RUNNER_UPDATE_FREQUENCY_MS";
const WORKER_THREADS_VAR: &str = "ENTRIES_JOB_RUNNER_WORKER_THREADS";
const MAX_BLOCKING_THREADS_VAR: &str = "ENTRIES_JOB_RUNNER_MAX_BLOCKING_THREADS";

const CLEAR_EXPIRED_CONTAINER_INVITES_JOB_FREQUENCY_SECS_VAR: &str =
    "ENTRIES_CLEAR_EXPIRED_CONTAINER_INVITES_JOB_FREQUENCY_SECS";
const CLEAR_EXPIRED_OTPS_JOB_FREQUENCY_SECS_VAR: &str =
    "ENTRIES_CLEAR_EXPIRED_OTPS_JOB_FREQUENCY_SECS";
const CLEAR_OLD_USER_DELETION_REQUESTS_JOB_FREQUENCY_SECS_VAR: &str =
    "ENTRIES_CLEAR_OLD_USER_DELETION_REQUESTS_JOB_FREQUENCY_SECS";
const CLEAR_UNVERIFIED_USERS_JOB_FREQUENCY_SECS_VAR: &str =
    "ENTRIES_CLEAR_UNVERIFIED_USERS_JOB_FREQUENCY_SECS";
const CLEAR_UNVERIFIED_USERS_MAX_USER_AGE_DAYS_VAR: &str =
    "ENTRIES_CLEAR_UNVERIFIED_USERS_MAX_USER_AGE_DAYS";
const DELETE_USERS_JOB_FREQUENCY_SECS_VAR: &str = "ENTRIES_DELETE_USERS_JOB_FREQUENCY_SECS";
const UNBLACKLIST_EXPIRED_TOKENS_JOB_FREQUENCY_SECS_VAR: &str =
    "ENTRIES_UNBLACKLIST_EXPIRED_TOKENS_JOB_FREQUENCY_SECS";

const LOG_LEVEL_VAR: &str = "ENTRIES_LOG_LEVEL";

pub static CONF: Lazy<Config> = Lazy::new(|| match Config::from_env() {
    Ok(c) => c,
    Err(e) => {
        eprintln!("ERROR: Failed to load configuration: {e}");

        if cfg!(test) {
            panic!();
        } else {
            std::process::exit(1);
        }
    }
});

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
    pub db_idle_timeout: Duration,

    #[zeroize(skip)]
    pub update_frequency: Duration,
    #[zeroize(skip)]
    pub worker_threads: usize,
    #[zeroize(skip)]
    pub max_blocking_threads: usize,

    #[zeroize(skip)]
    pub clear_expired_container_invites_job_frequency: Duration,
    #[zeroize(skip)]
    pub clear_expired_otps_job_frequency: Duration,
    #[zeroize(skip)]
    pub clear_old_user_deletion_requests_job_frequency: Duration,
    #[zeroize(skip)]
    pub clear_unverified_users_job_frequency: Duration,
    #[zeroize(skip)]
    pub clear_unverified_users_max_user_age_days: u64,
    #[zeroize(skip)]
    pub delete_users_job_frequency: Duration,
    #[zeroize(skip)]
    pub unblacklist_expired_tokens_job_frequency: Duration,

    #[zeroize(skip)]
    pub log_level: String,
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
        let inner = ConfigInner {
            db_username: env_var(DB_USERNAME_VAR)?,
            db_password: env_var(DB_PASSWORD_VAR)?,
            db_hostname: env_var(DB_HOSTNAME_VAR)?,
            db_port: env_var(DB_PORT_VAR)?,
            db_name: env_var(DB_NAME_VAR)?,
            db_max_connections: env_var_or(DB_MAX_CONNECTIONS_VAR, 48)?,
            db_idle_timeout: Duration::from_secs(env_var_or(DB_IDLE_TIMEOUT_SECS_VAR, 30)?),

            update_frequency: Duration::from_millis(env_var_or(UPDATE_FREQUENCY_MS_VAR, 5)?),
            worker_threads: env_var_or(WORKER_THREADS_VAR, num_cpus::get())?,
            max_blocking_threads: env_var_or(MAX_BLOCKING_THREADS_VAR, 40)?,

            clear_expired_container_invites_job_frequency: Duration::from_secs(env_var(
                CLEAR_EXPIRED_CONTAINER_INVITES_JOB_FREQUENCY_SECS_VAR,
            )?),
            clear_expired_otps_job_frequency: Duration::from_secs(env_var(
                CLEAR_EXPIRED_OTPS_JOB_FREQUENCY_SECS_VAR,
            )?),
            clear_old_user_deletion_requests_job_frequency: Duration::from_secs(env_var(
                CLEAR_OLD_USER_DELETION_REQUESTS_JOB_FREQUENCY_SECS_VAR,
            )?),
            clear_unverified_users_job_frequency: Duration::from_secs(env_var(
                CLEAR_UNVERIFIED_USERS_JOB_FREQUENCY_SECS_VAR,
            )?),
            clear_unverified_users_max_user_age_days: env_var_or(
                CLEAR_UNVERIFIED_USERS_MAX_USER_AGE_DAYS_VAR,
                7,
            )?,
            delete_users_job_frequency: Duration::from_secs(env_var(
                DELETE_USERS_JOB_FREQUENCY_SECS_VAR,
            )?),
            unblacklist_expired_tokens_job_frequency: Duration::from_secs(env_var(
                UNBLACKLIST_EXPIRED_TOKENS_JOB_FREQUENCY_SECS_VAR,
            )?),

            log_level: env_var_or(LOG_LEVEL_VAR, String::from("info"))?,
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

fn env_var_or<T: FromStr>(key: &'static str, default: T) -> Result<T, ConfigError> {
    let Ok(var) = std::env::var(key) else {
        return Ok(default);
    };

    var.parse().map_err(|_| ConfigError::invalid(key))
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
    use entries_common::db::{create_db_thread_pool, DbThreadPool};

    use super::*;

    pub static DB_THREAD_POOL: Lazy<DbThreadPool> = Lazy::new(|| {
        create_db_thread_pool(
            &format!(
                "postgres://{}:{}@{}:{}/{}",
                CONF.db_username, CONF.db_password, CONF.db_hostname, CONF.db_port, CONF.db_name,
            ),
            CONF.db_max_connections,
            CONF.db_idle_timeout,
        )
    });
}
