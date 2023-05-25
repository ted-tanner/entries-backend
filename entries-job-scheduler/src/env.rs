use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::sync::RwLock;

#[derive(Debug, Deserialize, Serialize)]
pub struct Conf {
    pub connections: Connections,
    pub runner: RunnerConf,
    pub clear_throttle_table_job: ClearThrottleTableJob,
    pub clear_unverified_users_job: ClearUnverifiedUsersJobConf,
    pub delete_users_job: DeleteUsersJobConf,
    pub unblacklist_expired_tokens_job: UnblacklistExpiredTokensJobConf,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Connections {
    pub database_uri: String,
    pub max_db_connections: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RunnerConf {
    pub update_frequency_secs: u64,
    pub worker_threads: Option<usize>,
    pub max_blocking_threads: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClearThrottleTableJob {
    pub job_frequency_secs: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClearUnverifiedUsersJobConf {
    pub job_frequency_secs: u64,
    pub max_unverified_user_age_days: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeleteUsersJobConf {
    pub job_frequency_secs: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UnblacklistExpiredTokensJobConf {
    pub job_frequency_secs: u64,
}

lazy_static! {
    static ref CONF_FILE_PATH: RwLock<String> = RwLock::new(String::from("conf/jobs-conf.toml"));
    pub static ref CONF: Conf = build_conf();
}

fn build_conf() -> Conf {
    let conf_file_path = CONF_FILE_PATH.read().expect("Lock was poisoned");

    let mut conf_file = File::open::<&str>(conf_file_path.as_ref()).unwrap_or_else(|_| {
        eprintln!("ERROR: Expected configuration file at '{conf_file_path}'");
        std::process::exit(1);
    });

    let mut contents = String::new();
    conf_file.read_to_string(&mut contents).unwrap_or_else(|_| {
        eprintln!(
            "ERROR: Configuration file at '{conf_file_path}' should be a text file in the TOML format."
        );
        std::process::exit(1);
    });

    match toml::from_str::<Conf>(&contents) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ERROR: Parsing '{conf_file_path}' failed: {e}");
            std::process::exit(1);
        }
    }
}

pub fn initialize(conf_file_path: &str) {
    *CONF_FILE_PATH.write().expect("Lock was poisioned") = String::from(conf_file_path);

    // Forego lazy initialization in order to validate conf file
    lazy_static::initialize(&crate::env::CONF);
}

pub mod db {
    use entries_utils::db::{create_db_thread_pool, DbThreadPool};

    lazy_static! {
        pub static ref DB_THREAD_POOL: DbThreadPool = create_db_thread_pool(
            crate::env::CONF.connections.database_uri.as_str(),
            crate::env::CONF.connections.max_db_connections,
        );
    }
}

pub mod runner {
    use futures::lock::Mutex;
    use std::time::Duration;

    use super::*;
    use crate::runner::JobRunner;

    lazy_static! {
        pub static ref JOB_RUNNER: Mutex<JobRunner> = Mutex::new(JobRunner::new(
            Duration::from_secs(CONF.runner.update_frequency_secs)
        ));
    }
}
