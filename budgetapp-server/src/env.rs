use aes_gcm::{aead::KeyInit, Aes128Gcm};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::sync::RwLock;
use std::time::Duration;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct Conf {
    pub connections: Connections,
    pub hashing: Hashing,
    pub keys: Keys,
    pub lifetimes: Lifetimes,
    pub time_delays: TimeDelays,
    pub workers: Workers,
}

#[derive(Deserialize, Serialize)]
pub struct RawConf {
    pub connections: Connections,
    pub hashing: Hashing,
    pub keys: RawKeys,
    pub lifetimes: RawLifetimes,
    pub time_delays: TimeDelays,
    pub workers: Workers,
}

#[derive(Deserialize, Serialize)]
pub struct Connections {
    pub database_uri: String,
    pub max_db_connections: Option<u32>,
}

#[derive(Deserialize, Serialize)]
pub struct Hashing {
    pub hash_length: u32,
    pub hash_iterations: u32,
    pub hash_mem_size_kib: u32,
    pub hash_lanes: u32,
    pub salt_length_bytes: usize,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Keys {
    pub hashing_key: [u8; 32],
    pub token_signing_key: [u8; 64],
    pub otp_key: [u8; 64],
    // Will already be zeroized by the aes_gcm crate with the zeroize feature
    #[zeroize(skip)]
    pub token_encryption_cipher: Aes128Gcm,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct RawKeys {
    pub hashing_key_b64: String,
    pub token_signing_key_b64: String,
    pub token_encryption_key_b64: String,
    pub otp_key_b64: String,
}

pub struct Lifetimes {
    pub access_token_lifetime: Duration,
    pub refresh_token_lifetime: Duration,
    pub signin_token_lifetime: Duration,
    pub user_creation_token_lifetime: Duration,
    pub user_deletion_token_lifetime: Duration,
    pub otp_lifetime: Duration,
}

#[derive(Deserialize, Serialize)]
pub struct RawLifetimes {
    pub access_token_lifetime_mins: u64,
    pub refresh_token_lifetime_days: u64,
    pub signin_token_lifetime_mins: u64,
    pub user_creation_token_lifetime_days: u64,
    pub user_deletion_token_lifetime_days: u64,
    pub otp_lifetime_mins: u64,
}

#[derive(Deserialize, Serialize)]
pub struct TimeDelays {
    pub user_deletion_delay_days: u64,
}

#[derive(Deserialize, Serialize)]
pub struct Workers {
    pub actix_workers: Option<usize>,
}

lazy_static! {
    static ref CONF_FILE_PATH: RwLock<String> = RwLock::new(String::from("conf/server-conf.toml"));
    pub static ref CONF: Conf = match build_conf() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CONFIGURATION ERROR: {e}");
            std::process::exit(1);
        }
    };
}

fn build_conf() -> Result<Conf, String> {
    let conf_file_path = CONF_FILE_PATH.read().expect("Lock was poisoned");

    let mut conf_file = match File::open::<&str>(conf_file_path.as_ref()) {
        Ok(f) => f,
        Err(e) => {
            return Err(format!(
                "Couldn't open configuration file at '{conf_file_path}': {e}"
            ))
        }
    };

    let mut contents = String::new();
    match conf_file.read_to_string(&mut contents) {
        Ok(_) => (),
        Err(_) => {
            return Err(format!(
                "Configuration file at '{conf_file_path}' should be a text file in the TOML format"
            ));
        }
    }

    let raw_conf = match toml::from_str::<RawConf>(&contents) {
        Ok(t) => t,
        Err(e) => return Err(format!("Parsing '{conf_file_path}' failed: {e}")),
    };

    if raw_conf.lifetimes.signin_token_lifetime_mins < raw_conf.lifetimes.otp_lifetime_mins * 2 {
        return Err(format!(
            "Sign-in token lifetime must be at least double the OTP lifetime in '{conf_file_path}'"
        ));
    }

    const HASHING_KEY_SIZE: usize = 32;
    let hashing_key = match base64::decode(&raw_conf.keys.hashing_key_b64) {
        Ok(k) => k,
        Err(e) => {
            return Err(format!(
                "Failed to base64 decode hashing_key_b64 from '{conf_file_path}': {e}"
            ))
        }
    };

    let hashing_key: [u8; HASHING_KEY_SIZE] = match hashing_key.try_into() {
        Ok(k) => k,
        Err(_) => {
            return Err(format!(
            "hashing_key_b64 in '{conf_file_path}' must have a size of {HASHING_KEY_SIZE} bytes"
            ))
        }
    };

    const OTP_KEY_SIZE: usize = 64;
    let otp_key = match base64::decode(&raw_conf.keys.otp_key_b64) {
        Ok(k) => k,
        Err(e) => {
            return Err(format!(
                "Failed to base64 decode otp_key_b64 from '{conf_file_path}': {e}"
            ))
        }
    };

    let otp_key: [u8; OTP_KEY_SIZE] = match otp_key.try_into() {
        Ok(k) => k,
        Err(_) => {
            return Err(format!(
                "otp_key_b64 in '{conf_file_path}' must have a size of {OTP_KEY_SIZE} bytes"
            ))
        }
    };

    const TOKEN_SIGNING_KEY_SIZE: usize = 64;
    let token_signing_key = match base64::decode(&raw_conf.keys.token_signing_key_b64) {
        Ok(k) => k,
        Err(e) => {
            return Err(format!(
                "Failed to base64 decode token_signing_key_b64 from '{conf_file_path}': {e}"
            ))
        }
    };

    let token_signing_key: [u8; TOKEN_SIGNING_KEY_SIZE] = match token_signing_key.try_into() {
        Ok(k) => k,
        Err(_) => {
            return Err(format!(
            "signing_key_b64 in '{conf_file_path}' must have a size of {TOKEN_SIGNING_KEY_SIZE} bytes"
            ))
        },
    };

    const TOKEN_ENCRYPTION_KEY_SIZE: usize = 16;
    let token_encryption_key = match base64::decode(&raw_conf.keys.token_encryption_key_b64) {
        Ok(k) => k,
        Err(e) => {
            return Err(format!(
                "Failed to base64 decode token_encryption_key_b64 from '{conf_file_path}': {e}"
            ))
        }
    };

    let token_encryption_key: [u8; TOKEN_ENCRYPTION_KEY_SIZE] = match token_encryption_key.try_into() {
        Ok(k) => k,
        Err(_) => {
            return Err(format!(
            "encryption_key_b64 in '{conf_file_path}' must have a size of {TOKEN_ENCRYPTION_KEY_SIZE} bytes"
            ))
        },
    };

    Ok(Conf {
        connections: raw_conf.connections,
        hashing: raw_conf.hashing,
        keys: Keys {
            hashing_key,
            token_signing_key,
            otp_key,
            token_encryption_cipher: Aes128Gcm::new(&token_encryption_key.into()),
        },
        lifetimes: Lifetimes {
            access_token_lifetime: Duration::from_secs(
                raw_conf.lifetimes.access_token_lifetime_mins * 60,
            ),
            refresh_token_lifetime: Duration::from_secs(
                raw_conf.lifetimes.refresh_token_lifetime_days * 3600 * 24,
            ),
            signin_token_lifetime: Duration::from_secs(
                raw_conf.lifetimes.signin_token_lifetime_mins * 60,
            ),
            user_creation_token_lifetime: Duration::from_secs(
                raw_conf.lifetimes.user_creation_token_lifetime_days * 3600 * 24,
            ),
            user_deletion_token_lifetime: Duration::from_secs(
                raw_conf.lifetimes.user_deletion_token_lifetime_days * 3600 * 24,
            ),
            otp_lifetime: Duration::from_secs(raw_conf.lifetimes.otp_lifetime_mins * 60),
        },
        time_delays: raw_conf.time_delays,
        workers: raw_conf.workers,
    })
}

#[cfg(test)]
pub mod testing {
    use budgetapp_utils::db::{create_db_thread_pool, DbThreadPool};

    lazy_static! {
        pub static ref DB_THREAD_POOL: DbThreadPool = create_db_thread_pool(
            crate::env::CONF.connections.database_uri.as_str(),
            crate::env::CONF.connections.max_db_connections,
        );
    }
}

pub fn initialize(conf_file_path: &str) {
    *CONF_FILE_PATH.write().expect("Lock was poisioned") = String::from(conf_file_path);

    // Forego lazy initialization in order to validate conf file
    lazy_static::initialize(&crate::env::CONF);
}
