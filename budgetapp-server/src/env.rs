use budgetapp_utils::password_hasher::HashParams;

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;

#[derive(Deserialize, Serialize)]
pub struct Conf {
    pub connections: Connections,
    pub hashing: Hashing,
    pub keys: Keys,
    pub lifetimes: Lifetimes,
    pub security: Security,
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

#[derive(Deserialize, Serialize)]
pub struct Keys {
    pub hashing_key: String,
    pub token_signing_key: String,
    pub otp_key: String,
}

#[derive(Deserialize, Serialize)]
pub struct Lifetimes {
    pub access_token_lifetime_mins: u64,
    pub refresh_token_lifetime_days: u64,
    pub signin_token_lifetime_mins: u64,
    pub user_creation_token_lifetime_days: u64,
    pub user_deletion_token_lifetime_days: u64,
    pub otp_lifetime_mins: u64,
}

#[derive(Deserialize, Serialize)]
pub struct Security {
    pub otp_max_attempts: i16,
    pub otp_attempts_reset_mins: u64,
    pub password_max_attempts: i16,
    pub password_attempts_reset_mins: u64,
    pub password_min_len_chars: usize,
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
    pub static ref APP_NAME: &'static str = "Budget App";
    pub static ref CONF: Conf = build_conf();
    pub static ref PASSWORD_HASHING_PARAMS: HashParams = HashParams {
        salt_len: CONF.hashing.salt_length_bytes,
        hash_len: CONF.hashing.hash_length,
        hash_iterations: CONF.hashing.hash_iterations,
        hash_mem_size_kib: CONF.hashing.hash_mem_size_kib,
        hash_lanes: CONF.hashing.hash_lanes,
    };
}

fn build_conf() -> Conf {
    const CONF_FILE_PATH: &str = "conf/server-conf.toml";

    let mut conf_file = File::open(CONF_FILE_PATH).unwrap_or_else(|_| {
        eprintln!("ERROR: Expected configuration file at '{}'", CONF_FILE_PATH);
        std::process::exit(1);
    });

    let mut contents = String::new();
    conf_file.read_to_string(&mut contents).unwrap_or_else(|_| {
        eprintln!(
            "ERROR: Configuration file at '{}' should be a text file in the TOML format.",
            CONF_FILE_PATH
        );
        std::process::exit(1);
    });

    match toml::from_str::<Conf>(&contents) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ERROR: Parsing '{}' failed: {}", CONF_FILE_PATH, e);
            std::process::exit(1);
        }
    }
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

pub fn initialize() {
    // Forego lazy initialization in order to validate conf file
    if !CONF.hashing.hash_mem_size_kib.is_power_of_two() {
        eprintln!(
            "ERROR: Hash memory size must be a power of two. {} is not a power of two.",
            CONF.hashing.hash_mem_size_kib
        );
        std::process::exit(1);
    }

    if CONF.lifetimes.signin_token_lifetime_mins < CONF.lifetimes.otp_lifetime_mins * 2 {
        eprintln!("ERROR: Sign-in token lifetime must be at least double the OTP lifetime.");
        std::process::exit(1);
    }
}
