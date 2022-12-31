use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;

#[derive(Debug, Deserialize, Serialize)]
pub struct Conf {
    pub connections: Connections,
    pub runner: RunnerConf,
    pub clear_otp_attempts_job: ClearOtpAttemptsJob,
    pub clear_password_attempts_job: ClearPasswordAttemptsJob,
    pub delete_users_job: DeleteUsersJob,
    pub unblacklist_expired_refresh_tokens_job: UnblacklistExpiredRefreshTokensJob,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Connections {
    pub database_uri: String,
    pub max_db_connections: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RunnerConf {
    pub update_frequency_secs: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClearOtpAttemptsJob {
    pub job_frequency_secs: u64,
    pub attempts_lifetime_mins: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClearPasswordAttemptsJob {
    pub job_frequency_secs: u64,
    pub attempts_lifetime_mins: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeleteUsersJob {
    pub job_frequency_secs: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UnblacklistExpiredRefreshTokensJob {
    pub job_frequency_secs: u64,
}

lazy_static! {
    pub static ref CONF: Conf = build_conf();
}

fn build_conf() -> Conf {
    const CONF_FILE_PATH: &str = "conf/jobs-conf.toml";

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

pub mod db {
    use budgetapp_utils::db::{create_db_thread_pool, DbThreadPool};

    lazy_static! {
        pub static ref DB_THREAD_POOL: DbThreadPool = create_db_thread_pool(
            crate::env::CONF.connections.database_uri.as_str(),
            crate::env::CONF.connections.max_db_connections,
        );
    }
}

pub mod runner {
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;
    use crate::runner::JobRunner;

    lazy_static! {
        pub static ref JOB_RUNNER: Mutex<JobRunner> = Mutex::new(JobRunner::new(
            Duration::from_secs(CONF.runner.update_frequency_secs)
        ));
    }
}
