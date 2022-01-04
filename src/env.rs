lazy_static! {
    pub static ref APP_NAME: &'static str = "Budget App";
}

pub mod db {
    lazy_static! {
        pub static ref DATABASE_URL: String =
            std::env::var("DATABASE_URL").expect("DATABASE_URL environment variable must be set");
    }

    pub fn validate() {
        let _ = *DATABASE_URL;
    }
}

pub mod hashing {
    const DEFAULT_HASH_LENGTH: u32 = 64;
    const DEFAULT_HASH_ITERATIONS: u32 = 16;
    const DEFAULT_HASH_MEM_SIZE_KIB: u32 = 262144;
    const DEFAULT_SALT_LENGTH_BYTES: usize = 32;

    lazy_static! {
        pub static ref HASHING_SECRET_KEY: Vec<u8> = std::env::var("HASHING_SECRET_KEY")
            .expect("HASHING_SECRET_KEY environment variable must be set")
            .as_bytes().to_owned();
        pub static ref HASH_LENGTH: u32 = std::env::var("HASH_LENGTH")
            .unwrap_or(DEFAULT_HASH_LENGTH.to_string())
            .parse::<u32>()
            .expect("HASH_LENGTH environment variable must be an unsigned 32-bit integer");
        pub static ref HASH_ITERATIONS: u32 = std::env::var("HASH_ITERATIONS")
            .unwrap_or(DEFAULT_HASH_ITERATIONS.to_string())
            .parse::<u32>()
            .expect("HASH_ITERATIONS environment variable must be an unsigned 32-bit integer");
        pub static ref HASH_MEM_SIZE_KIB: u32 = std::env::var("HASH_MEM_SIZE_KIB")
            .unwrap_or(DEFAULT_HASH_MEM_SIZE_KIB.to_string())
            .parse::<u32>()
            .expect("HASH_MEM_SIZE_KIB environment variable must be an unsigned 32-bit integer");
        pub static ref SALT_LENGTH_BYTES: usize = std::env::var("SALT_LENGTH_BYTES")
            .unwrap_or(DEFAULT_SALT_LENGTH_BYTES.to_string())
            .parse::<usize>()
            .expect("SALT_LENGTH_BYTES environment variable must be an unsigned integer matching the processor's instructon bit lenth");
    }

    pub fn validate() {
        let _ = *HASHING_SECRET_KEY;
        let _ = *HASH_LENGTH;
        let _ = *HASH_ITERATIONS;
        let _ = *HASH_MEM_SIZE_KIB;
        let _ = *SALT_LENGTH_BYTES;

        if !HASH_MEM_SIZE_KIB.is_power_of_two() {
            panic!("HASH_MEM_SIZE_KIB environment variable must be a power of two");
        }
    }
}

pub mod jwt {
    const DEFAULT_ACCESS_TOKEN_LIFETIME_MINS: u64 = 8;
    const DEFAULT_REFRESH_TOKEN_LIFETIME_DAYS: u64 = 28;

    lazy_static! {
        pub static ref SIGNING_SECRET_KEY: Vec<u8> = std::env::var("SIGNING_SECRET_KEY")
            .expect("SIGNING_SECRET_KEY environment variable must be set")
            .as_bytes().to_owned();
        pub static ref ACCESS_LIFETIME_SECS: u64 = std::env::var("ACCESS_TOKEN_LIFETIME_MINS")
            .unwrap_or(DEFAULT_ACCESS_TOKEN_LIFETIME_MINS.to_string())
            .parse::<u64>()
            .expect("ACCESS_TOKEN_LIFETIME_MINS environment variable must be an unsigned 64-bit integer")
            * 60;
        pub static ref REFRESH_LIFETIME_SECS: u64 = std::env::var("REFRESH_TOKEN_LIFETIME_DAYS")
            .unwrap_or(DEFAULT_REFRESH_TOKEN_LIFETIME_DAYS.to_string())
            .parse::<u64>()
            .expect("REFRESH_TOKEN_LIFETIME_DAYS environment variable must be an unsigned 64-bit integer")
            * 24
            * 60
            * 60;
    }

    pub fn validate() {
        let _ = *SIGNING_SECRET_KEY;
        let _ = *ACCESS_LIFETIME_SECS;
        let _ = *REFRESH_LIFETIME_SECS;
    }
}

pub mod otp {
    const DEFAULT_OTP_LIFETIME_MINS: u64 = 8;

    lazy_static! {
        pub static ref OTP_SECRET_KEY: Vec<u8> = std::env::var("OTP_SECRET_KEY")
            .expect("OTP_SECRET_KEY environment variable must be set")
            .as_bytes().to_owned();
        pub static ref OTP_LIFETIME_SECS: u64 = std::env::var("OTP_LIFETIME_MINS")
            .unwrap_or(DEFAULT_OTP_LIFETIME_MINS.to_string())
            .parse::<u64>()
            .expect("OTP_LIFETIME_MINS environment variable must be an unsigned 64-bit integer")
            * 60;
    }
}

pub mod password {
    use crate::utils::common_password_tree::CommonPasswordTree;

    lazy_static! {
        pub static ref COMMON_PASSWORDS_FILE_PATH: &'static str = "./assets/common-passwords.txt";
        pub static ref COMMON_PASSWORDS_TREE: CommonPasswordTree = CommonPasswordTree::generate();
    }

    pub fn validate() {
        let _ = *COMMON_PASSWORDS_FILE_PATH;
        let _ = *COMMON_PASSWORDS_TREE;
    }
}

pub mod rand {
    use ring::rand::SystemRandom;

    lazy_static! {
        pub static ref SECURE_RANDOM_GENERATOR: SystemRandom = SystemRandom::new();
    }

    pub fn validate() {
        let _ = *SECURE_RANDOM_GENERATOR;
    }
}

pub mod testing {
    use crate::definitions::ThreadPool;

    use diesel::prelude::*;
    use diesel::r2d2::{self, ConnectionManager};

    lazy_static! {
        pub static ref THREAD_POOL: ThreadPool = r2d2::Pool::builder()
            .build(ConnectionManager::<PgConnection>::new(
                crate::env::db::DATABASE_URL.as_str()
            ))
            .unwrap();
    }
}

pub fn validate() {
    // Forego lazy initialization in order to validate environment variables
    db::validate();
    hashing::validate();
    jwt::validate();
    password::validate();
    rand::validate();
}
