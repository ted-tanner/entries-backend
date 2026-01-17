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

const DB_USERNAME_VAR: &str = "ENTRIES_DB_USERNAME";
const DB_PASSWORD_VAR: &str = "ENTRIES_DB_PASSWORD";
const DB_HOSTNAME_VAR: &str = "ENTRIES_DB_HOSTNAME";
const DB_PORT_VAR: &str = "ENTRIES_DB_PORT";
const DB_NAME_VAR: &str = "ENTRIES_DB_NAME";
const DB_MAX_CONNECTIONS_VAR: &str = "ENTRIES_DB_MAX_CONNECTIONS";
const DB_IDLE_TIMEOUT_SECS_VAR: &str = "ENTRIES_DB_IDLE_TIMEOUT_SECS";

const AUTH_STRING_HASH_KEY_VAR: &str = "ENTRIES_AUTH_STRING_HASH_KEY_B64";
const TOKEN_SIGNING_KEY_VAR: &str = "ENTRIES_TOKEN_SIGNING_KEY_B64";
const AMAZON_SES_USERNAME_VAR: &str = "ENTRIES_AMAZON_SES_USERNAME";
const AMAZON_SES_KEY_VAR: &str = "ENTRIES_AMAZON_SES_KEY";

const AUTH_STRING_HASH_LENGTH_VAR: &str = "ENTRIES_AUTH_STRING_HASH_LENGTH";
const AUTH_STRING_HASH_ITERATIONS_VAR: &str = "ENTRIES_AUTH_STRING_HASH_ITERATIONS";
const AUTH_STRING_HASH_MEM_COST_KIB_VAR: &str = "ENTRIES_AUTH_STRING_HASH_MEM_COST_KIB";
const AUTH_STRING_HASH_THREADS_VAR: &str = "ENTRIES_AUTH_STRING_HASH_THREADS";
const AUTH_STRING_HASH_SALT_LENGTH_VAR: &str = "ENTRIES_AUTH_STRING_HASH_SALT_LENGTH";

const CLIENT_AUTH_STRING_HASH_ITERATIONS_VAR: &str = "ENTRIES_CLIENT_AUTH_STRING_HASH_ITERATIONS";
const CLIENT_AUTH_STRING_HASH_MEM_COST_KIB_VAR: &str =
    "ENTRIES_CLIENT_AUTH_STRING_HASH_MEM_COST_KIB";
const CLIENT_AUTH_STRING_HASH_THREADS_VAR: &str = "ENTRIES_CLIENT_AUTH_STRING_HASH_THREADS";

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
const USER_DELETION_DELAY_DAYS_VAR: &str = "ENTRIES_USER_DELETION_DELAY_DAYS";

const ACTIX_WORKER_COUNT_VAR: &str = "ENTRIES_ACTIX_WORKER_COUNT";
const LOG_LEVEL_VAR: &str = "ENTRIES_LOG_LEVEL";
const PROTOBUF_MAX_SIZE_MB_VAR: &str = "ENTRIES_PROTOBUF_MAX_SIZE_MB";

const SIGNIN_LIMITER_MAX_PER_PERIOD_VAR: &str = "ENTRIES_SIGNIN_LIMITER_MAX_PER_PERIOD";
const SIGNIN_LIMITER_PERIOD_SECS_VAR: &str = "ENTRIES_SIGNIN_LIMITER_PERIOD_SECS";
const SIGNIN_LIMITER_FREQUENCY_HOURS_VAR: &str = "ENTRIES_SIGNIN_LIMITER_FREQUENCY_HOURS";

const API_CREATE_CONTAINER_LIMITER_MAX_PER_PERIOD_VAR: &str =
    "ENTRIES_API_CREATE_CONTAINER_LIMITER_MAX_PER_PERIOD";
const API_CREATE_CONTAINER_LIMITER_PERIOD_SECS_VAR: &str =
    "ENTRIES_API_CREATE_CONTAINER_LIMITER_PERIOD_SECS";
const API_GET_CONTAINERS_LIMITER_MAX_PER_PERIOD_VAR: &str =
    "ENTRIES_API_GET_CONTAINERS_LIMITER_MAX_PER_PERIOD";
const API_GET_CONTAINERS_LIMITER_PERIOD_SECS_VAR: &str =
    "ENTRIES_API_GET_CONTAINERS_LIMITER_PERIOD_SECS";
const API_CONTAINER_INVITE_LIMITER_MAX_PER_PERIOD_VAR: &str =
    "ENTRIES_API_CONTAINER_INVITE_LIMITER_MAX_PER_PERIOD";
const API_CONTAINER_INVITE_LIMITER_PERIOD_SECS_VAR: &str =
    "ENTRIES_API_CONTAINER_INVITE_LIMITER_PERIOD_SECS";
const API_KEY_LOOKUP_LIMITER_MAX_PER_PERIOD_VAR: &str =
    "ENTRIES_API_KEY_LOOKUP_LIMITER_MAX_PER_PERIOD";
const API_KEY_LOOKUP_LIMITER_PERIOD_SECS_VAR: &str = "ENTRIES_API_KEY_LOOKUP_LIMITER_PERIOD_SECS";
const API_CREATE_USER_LIMITER_MAX_PER_PERIOD_VAR: &str =
    "ENTRIES_API_CREATE_USER_LIMITER_MAX_PER_PERIOD";
const API_CREATE_USER_LIMITER_PERIOD_SECS_VAR: &str = "ENTRIES_API_CREATE_USER_LIMITER_PERIOD_SECS";
const API_CREATE_OBJECT_LIMITER_MAX_PER_PERIOD_VAR: &str =
    "ENTRIES_API_CREATE_OBJECT_LIMITER_MAX_PER_PERIOD";
const API_CREATE_OBJECT_LIMITER_PERIOD_SECS_VAR: &str =
    "ENTRIES_API_CREATE_OBJECT_LIMITER_PERIOD_SECS";
const API_PASSWORD_LIMITER_MAX_PER_PERIOD_VAR: &str = "ENTRIES_API_PASSWORD_LIMITER_MAX_PER_PERIOD";
const API_PASSWORD_LIMITER_PERIOD_SECS_VAR: &str = "ENTRIES_API_PASSWORD_LIMITER_PERIOD_SECS";
const API_RECOVERY_LIMITER_MAX_PER_PERIOD_VAR: &str = "ENTRIES_API_RECOVERY_LIMITER_MAX_PER_PERIOD";
const API_RECOVERY_LIMITER_PERIOD_SECS_VAR: &str = "ENTRIES_API_RECOVERY_LIMITER_PERIOD_SECS";
const API_VERIFY_OTP_LIMITER_MAX_PER_PERIOD_VAR: &str =
    "ENTRIES_API_VERIFY_OTP_LIMITER_MAX_PER_PERIOD";
const API_VERIFY_OTP_LIMITER_PERIOD_SECS_VAR: &str = "ENTRIES_API_VERIFY_OTP_LIMITER_PERIOD_SECS";
const API_EMAIL_LIMITER_MAX_PER_PERIOD_VAR: &str = "ENTRIES_API_EMAIL_LIMITER_MAX_PER_PERIOD";
const API_EMAIL_LIMITER_PERIOD_SECS_VAR: &str = "ENTRIES_API_EMAIL_LIMITER_PERIOD_SECS";
const API_REFRESH_TOKENS_LIMITER_MAX_PER_PERIOD_VAR: &str =
    "ENTRIES_API_REFRESH_TOKENS_LIMITER_MAX_PER_PERIOD";
const API_REFRESH_TOKENS_LIMITER_PERIOD_SECS_VAR: &str =
    "ENTRIES_API_REFRESH_TOKENS_LIMITER_PERIOD_SECS";
const API_CHANGE_EMAIL_LIMITER_MAX_PER_PERIOD_VAR: &str =
    "ENTRIES_API_CHANGE_EMAIL_LIMITER_MAX_PER_PERIOD";
const API_CHANGE_EMAIL_LIMITER_PERIOD_SECS_VAR: &str =
    "ENTRIES_API_CHANGE_EMAIL_LIMITER_PERIOD_SECS";
const API_LIMITER_CLEAR_FREQUENCY_HOURS_VAR: &str = "ENTRIES_API_LIMITER_CLEAR_FREQUENCY_HOURS";

const API_LIMITER_WARN_EVERY_OVER_LIMIT_VAR: &str = "ENTRIES_API_LIMITER_WARN_EVERY_OVER_LIMIT";

const MAX_SMALL_OBJECT_SIZE_KB_VAR: &str = "ENTRIES_MAX_SMALL_OBJECT_SIZE_KB";
const MAX_KEYSTORE_SIZE_KB_VAR: &str = "ENTRIES_MAX_KEYSTORE_SIZE_KB";
const MAX_USER_PREFERENCES_SIZE_KB_VAR: &str = "ENTRIES_MAX_USER_PREFERENCES_SIZE_KB";
const MAX_ENCRYPTION_KEY_SIZE_KB_VAR: &str = "ENTRIES_MAX_ENCRYPTION_KEY_SIZE_KB";
const MAX_CONTAINERS_VAR: &str = "ENTRIES_MAX_CONTAINERS";
const MAX_CONTAINER_FETCH_COUNT_VAR: &str = "ENTRIES_MAX_CONTAINER_FETCH_COUNT";
const MAX_AUTH_STRING_LENGTH_VAR: &str = "ENTRIES_MAX_AUTH_STRING_LENGTH";

const HEALTH_ENDPOINT_KEY_VAR: &str = "ENTRIES_HEALTH_ENDPOINT_KEY";
const CLIENT_ERRORS_ENDPOINT_KEY_VAR: &str = "ENTRIES_CLIENT_ERRORS_ENDPOINT_KEY";

const AUTH_STRING_AUTH_STRING_HASH_KEY_SIZE: usize = 32;
const TOKEN_SIGNING_KEY_SIZE: usize = 64;

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

    pub auth_string_hash_key: [u8; AUTH_STRING_AUTH_STRING_HASH_KEY_SIZE],
    pub token_signing_key: [u8; TOKEN_SIGNING_KEY_SIZE],
    pub amazon_ses_username: String,
    pub amazon_ses_key: String,

    pub auth_string_hash_length: u32,
    pub auth_string_hash_iterations: u32,
    pub auth_string_hash_mem_cost_kib: u32,
    pub auth_string_hash_threads: u32,
    pub auth_string_hash_salt_length: u32,

    pub client_auth_string_hash_iterations: i32,
    pub client_auth_string_hash_mem_cost_kib: i32,
    pub client_auth_string_hash_threads: i32,

    pub email_enabled: bool,
    #[zeroize(skip)]
    pub email_from_address: Mailbox,
    #[zeroize(skip)]
    pub email_reply_to_address: Mailbox,
    pub smtp_address: String,
    #[zeroize(skip)]
    pub max_smtp_connections: u32,
    #[zeroize(skip)]
    pub smtp_idle_timeout: Duration,

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
    pub user_deletion_delay_days: u64,

    #[zeroize(skip)]
    pub signin_limiter_max_per_period: u32,
    #[zeroize(skip)]
    pub signin_limiter_period: Duration,
    #[zeroize(skip)]
    pub signin_limiter_clear_frequency: Duration,

    #[zeroize(skip)]
    pub actix_worker_count: usize,
    #[zeroize(skip)]
    pub log_level: String,
    #[zeroize(skip)]
    pub protobuf_max_size: usize,

    #[zeroize(skip)]
    pub max_small_object_size: usize,
    #[zeroize(skip)]
    pub max_keystore_size: usize,
    #[zeroize(skip)]
    pub max_user_preferences_size: usize,
    #[zeroize(skip)]
    pub max_encryption_key_size: usize,
    #[zeroize(skip)]
    pub max_containers: usize,
    #[zeroize(skip)]
    pub max_container_fetch_count: usize,
    #[zeroize(skip)]
    pub max_auth_string_length: usize,

    pub health_endpoint_key: String,
    pub client_errors_endpoint_key: String,

    #[zeroize(skip)]
    pub api_create_container_limiter_max_per_period: u64,
    #[zeroize(skip)]
    pub api_create_container_limiter_period: Duration,
    #[zeroize(skip)]
    pub api_get_containers_limiter_max_per_period: u64,
    #[zeroize(skip)]
    pub api_get_containers_limiter_period: Duration,
    #[zeroize(skip)]
    pub api_container_invite_limiter_max_per_period: u64,
    #[zeroize(skip)]
    pub api_container_invite_limiter_period: Duration,
    #[zeroize(skip)]
    pub api_key_lookup_limiter_max_per_period: u64,
    #[zeroize(skip)]
    pub api_key_lookup_limiter_period: Duration,
    #[zeroize(skip)]
    pub api_create_user_limiter_max_per_period: u64,
    #[zeroize(skip)]
    pub api_create_user_limiter_period: Duration,
    #[zeroize(skip)]
    pub api_create_object_limiter_max_per_period: u64,
    #[zeroize(skip)]
    pub api_create_object_limiter_period: Duration,
    #[zeroize(skip)]
    pub api_password_limiter_max_per_period: u64,
    #[zeroize(skip)]
    pub api_password_limiter_period: Duration,
    #[zeroize(skip)]
    pub api_recovery_limiter_max_per_period: u64,
    #[zeroize(skip)]
    pub api_recovery_limiter_period: Duration,
    #[zeroize(skip)]
    pub api_verify_otp_limiter_max_per_period: u64,
    #[zeroize(skip)]
    pub api_verify_otp_limiter_period: Duration,
    #[zeroize(skip)]
    pub api_email_limiter_max_per_period: u64,
    #[zeroize(skip)]
    pub api_email_limiter_period: Duration,
    #[zeroize(skip)]
    pub api_refresh_tokens_limiter_max_per_period: u64,
    #[zeroize(skip)]
    pub api_refresh_tokens_limiter_period: Duration,
    #[zeroize(skip)]
    pub api_change_email_limiter_max_per_period: u64,
    #[zeroize(skip)]
    pub api_change_email_limiter_period: Duration,
    #[zeroize(skip)]
    pub api_limiter_clear_frequency: Duration,

    /// When a request is blocked by an API limiter, emit a WARN log every N blocked requests
    /// above the limit (per key/subnet). Set to 0 to disable.
    #[zeroize(skip)]
    pub api_limiter_warn_every_over_limit: u32,
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
        let auth_string_hash_key = Zeroizing::new(
            b64.decode(env_var::<String>(AUTH_STRING_HASH_KEY_VAR)?.as_bytes())
                .map_err(|_| ConfigError::InvalidVar(AUTH_STRING_HASH_KEY_VAR))?,
        );
        let auth_string_hash_key = auth_string_hash_key[..AUTH_STRING_AUTH_STRING_HASH_KEY_SIZE]
            .try_into()
            .map_err(|_| ConfigError::InvalidVar(AUTH_STRING_HASH_KEY_VAR))?;

        let token_signing_key = Zeroizing::new(
            b64.decode(env_var::<String>(TOKEN_SIGNING_KEY_VAR)?.as_bytes())
                .map_err(|_| ConfigError::InvalidVar(TOKEN_SIGNING_KEY_VAR))?,
        );
        let token_signing_key = token_signing_key[..TOKEN_SIGNING_KEY_SIZE]
            .try_into()
            .map_err(|_| ConfigError::InvalidVar(TOKEN_SIGNING_KEY_VAR))?;

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
            db_max_connections: env_var_or(DB_MAX_CONNECTIONS_VAR, 48)?,
            db_idle_timeout: Duration::from_secs(env_var_or(DB_IDLE_TIMEOUT_SECS_VAR, 30)?),

            auth_string_hash_key,
            token_signing_key,
            amazon_ses_username: env_var(AMAZON_SES_USERNAME_VAR)?,
            amazon_ses_key: env_var(AMAZON_SES_KEY_VAR)?,

            auth_string_hash_length: env_var(AUTH_STRING_HASH_LENGTH_VAR)?,
            auth_string_hash_iterations: env_var(AUTH_STRING_HASH_ITERATIONS_VAR)?,
            auth_string_hash_mem_cost_kib: env_var(AUTH_STRING_HASH_MEM_COST_KIB_VAR)?,
            auth_string_hash_threads: env_var(AUTH_STRING_HASH_THREADS_VAR)?,
            auth_string_hash_salt_length: env_var(AUTH_STRING_HASH_SALT_LENGTH_VAR)?,

            client_auth_string_hash_iterations: env_var(CLIENT_AUTH_STRING_HASH_ITERATIONS_VAR)?,
            client_auth_string_hash_mem_cost_kib: env_var(
                CLIENT_AUTH_STRING_HASH_MEM_COST_KIB_VAR,
            )?,
            client_auth_string_hash_threads: env_var(CLIENT_AUTH_STRING_HASH_THREADS_VAR)?,

            email_enabled: if cfg!(test) {
                false
            } else {
                env_var(EMAIL_ENABLED_VAR)?
            },
            email_from_address,
            email_reply_to_address,
            smtp_address: env_var(SMTP_ADDRESS_VAR)?,
            max_smtp_connections: env_var_or(MAX_SMTP_CONNECTIONS_VAR, 24)?,
            smtp_idle_timeout: Duration::from_secs(env_var_or(SMTP_IDLE_TIMEOUT_SECS_VAR, 60)?),

            user_verification_url: env_var(USER_VERIFICATION_URL_VAR)?,
            user_deletion_url: env_var(USER_DELETION_URL_VAR)?,

            access_token_lifetime: Duration::from_secs(
                env_var_or(ACCESS_TOKEN_LIFETIME_MINS_VAR, 15)? * 60,
            ),
            refresh_token_lifetime: Duration::from_secs(
                env_var_or(REFRESH_TOKEN_LIFETIME_DAYS_VAR, 30)? * 86400,
            ),
            signin_token_lifetime: Duration::from_secs(
                env_var_or(SIGNIN_TOKEN_LIFETIME_MINS_VAR, 30)? * 60,
            ),
            user_creation_token_lifetime: Duration::from_secs(
                env_var_or(USER_CREATION_TOKEN_LIFETIME_DAYS_VAR, 7)? * 86400,
            ),
            user_deletion_token_lifetime: Duration::from_secs(
                env_var_or(USER_DELETION_TOKEN_LIFETIME_DAYS_VAR, 7)? * 86400,
            ),
            otp_lifetime: Duration::from_secs(env_var_or(OTP_LIFETIME_MINS_VAR, 15)? * 60),
            user_deletion_delay_days: env_var_or(USER_DELETION_DELAY_DAYS_VAR, 7)?,

            signin_limiter_max_per_period: env_var_or(SIGNIN_LIMITER_MAX_PER_PERIOD_VAR, 6)?,
            signin_limiter_period: Duration::from_secs(env_var_or(
                SIGNIN_LIMITER_PERIOD_SECS_VAR,
                600,
            )?),
            signin_limiter_clear_frequency: Duration::from_secs(
                env_var_or(SIGNIN_LIMITER_FREQUENCY_HOURS_VAR, 24)? * 3600,
            ),

            actix_worker_count: env_var_or(ACTIX_WORKER_COUNT_VAR, num_cpus::get())?,
            log_level: env_var_or(LOG_LEVEL_VAR, String::from("info"))?,
            protobuf_max_size: env_var_or(PROTOBUF_MAX_SIZE_MB_VAR, 100)? * 1024 * 1024,

            max_small_object_size: env_var_or(MAX_SMALL_OBJECT_SIZE_KB_VAR, 4)? * 1024,
            max_keystore_size: env_var_or(MAX_KEYSTORE_SIZE_KB_VAR, 80_000)? * 1024,
            max_user_preferences_size: env_var_or(MAX_USER_PREFERENCES_SIZE_KB_VAR, 32)? * 1024,
            max_encryption_key_size: env_var_or(MAX_ENCRYPTION_KEY_SIZE_KB_VAR, 4)? * 1024,
            max_containers: env_var_or(MAX_CONTAINERS_VAR, 5_000)?,
            max_container_fetch_count: env_var_or(MAX_CONTAINER_FETCH_COUNT_VAR, 50)?,
            max_auth_string_length: env_var_or(MAX_AUTH_STRING_LENGTH_VAR, 1024)?,

            health_endpoint_key: env_var(HEALTH_ENDPOINT_KEY_VAR)?,
            client_errors_endpoint_key: env_var(CLIENT_ERRORS_ENDPOINT_KEY_VAR)?,

            api_create_container_limiter_max_per_period: env_var_or(
                API_CREATE_CONTAINER_LIMITER_MAX_PER_PERIOD_VAR,
                10u64,
            )?,
            api_create_container_limiter_period: Duration::from_secs(env_var_or(
                API_CREATE_CONTAINER_LIMITER_PERIOD_SECS_VAR,
                120,
            )?),
            api_get_containers_limiter_max_per_period: env_var_or(
                API_GET_CONTAINERS_LIMITER_MAX_PER_PERIOD_VAR,
                20u64,
            )?,
            api_get_containers_limiter_period: Duration::from_secs(env_var_or(
                API_GET_CONTAINERS_LIMITER_PERIOD_SECS_VAR,
                10,
            )?),
            api_container_invite_limiter_max_per_period: env_var_or(
                API_CONTAINER_INVITE_LIMITER_MAX_PER_PERIOD_VAR,
                10u64,
            )?,
            api_container_invite_limiter_period: Duration::from_secs(env_var_or(
                API_CONTAINER_INVITE_LIMITER_PERIOD_SECS_VAR,
                120,
            )?),
            api_key_lookup_limiter_max_per_period: env_var_or(
                API_KEY_LOOKUP_LIMITER_MAX_PER_PERIOD_VAR,
                30u64,
            )?,
            api_key_lookup_limiter_period: Duration::from_secs(env_var_or(
                API_KEY_LOOKUP_LIMITER_PERIOD_SECS_VAR,
                180,
            )?),
            api_create_user_limiter_max_per_period: env_var_or(
                API_CREATE_USER_LIMITER_MAX_PER_PERIOD_VAR,
                5u64,
            )?,
            api_create_user_limiter_period: Duration::from_secs(env_var_or(
                API_CREATE_USER_LIMITER_PERIOD_SECS_VAR,
                1200,
            )?),
            api_create_object_limiter_max_per_period: env_var_or(
                API_CREATE_OBJECT_LIMITER_MAX_PER_PERIOD_VAR,
                10u64,
            )?,
            api_create_object_limiter_period: Duration::from_secs(env_var_or(
                API_CREATE_OBJECT_LIMITER_PERIOD_SECS_VAR,
                10,
            )?),
            api_password_limiter_max_per_period: env_var_or(
                API_PASSWORD_LIMITER_MAX_PER_PERIOD_VAR,
                6u64,
            )?,
            api_password_limiter_period: Duration::from_secs(env_var_or(
                API_PASSWORD_LIMITER_PERIOD_SECS_VAR,
                600,
            )?),
            api_recovery_limiter_max_per_period: env_var_or(
                API_RECOVERY_LIMITER_MAX_PER_PERIOD_VAR,
                2u64,
            )?,
            api_recovery_limiter_period: Duration::from_secs(env_var_or(
                API_RECOVERY_LIMITER_PERIOD_SECS_VAR,
                600,
            )?),
            api_verify_otp_limiter_max_per_period: env_var_or(
                API_VERIFY_OTP_LIMITER_MAX_PER_PERIOD_VAR,
                6u64,
            )?,
            api_verify_otp_limiter_period: Duration::from_secs(env_var_or(
                API_VERIFY_OTP_LIMITER_PERIOD_SECS_VAR,
                60,
            )?),
            api_email_limiter_max_per_period: env_var_or(
                API_EMAIL_LIMITER_MAX_PER_PERIOD_VAR,
                6u64,
            )?,
            api_email_limiter_period: Duration::from_secs(env_var_or(
                API_EMAIL_LIMITER_PERIOD_SECS_VAR,
                360,
            )?),
            api_refresh_tokens_limiter_max_per_period: env_var_or(
                API_REFRESH_TOKENS_LIMITER_MAX_PER_PERIOD_VAR,
                20u64,
            )?,
            api_refresh_tokens_limiter_period: Duration::from_secs(env_var_or(
                API_REFRESH_TOKENS_LIMITER_PERIOD_SECS_VAR,
                180,
            )?),
            api_change_email_limiter_max_per_period: env_var_or(
                API_CHANGE_EMAIL_LIMITER_MAX_PER_PERIOD_VAR,
                5u64,
            )?,
            api_change_email_limiter_period: Duration::from_secs(env_var_or(
                API_CHANGE_EMAIL_LIMITER_PERIOD_SECS_VAR,
                1200,
            )?),
            api_limiter_clear_frequency: Duration::from_secs(
                env_var_or(API_LIMITER_CLEAR_FREQUENCY_HOURS_VAR, 24)? * 3600,
            ),
            api_limiter_warn_every_over_limit: env_var_or(
                API_LIMITER_WARN_EVERY_OVER_LIMIT_VAR,
                50u32,
            )?,
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
            let inner = self.inner.get();
            (*inner).zeroize();
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
    use entries_common::db::{create_db_async_pool, DbAsyncPool};
    use entries_common::email::senders::MockSender;
    use entries_common::email::SendEmail;

    use std::sync::Arc;

    use super::*;

    pub static DB_ASYNC_POOL: Lazy<DbAsyncPool> = Lazy::new(|| {
        let db_uri = format!(
            "postgres://{}:{}@{}:{}/{}",
            CONF.db_username, CONF.db_password, CONF.db_hostname, CONF.db_port, CONF.db_name,
        );

        // Use futures::executor::block_on which works within async contexts
        futures::executor::block_on(create_db_async_pool(
            &db_uri,
            CONF.db_max_connections,
            CONF.db_idle_timeout,
        ))
    });

    pub static SMTP_THREAD_POOL: Lazy<Arc<Box<dyn SendEmail>>> =
        Lazy::new(|| Arc::new(Box::new(MockSender::new())));
}
