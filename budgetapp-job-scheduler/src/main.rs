#[macro_use]
extern crate lazy_static;

use env_logger::Env;

mod env;
mod jobs;
mod runner;

use jobs::{ClearOtpAttempts, ClearPasswordAttempts, UnblacklistExpiredRefreshTokens};

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let mut job_runner = env::runner::JOB_RUNNER
        .lock()
        .expect("Job runner lock was poisioned");
    job_runner.register(Box::new(ClearOtpAttempts::new()));
    job_runner.register(Box::new(ClearPasswordAttempts::new()));
    job_runner.register(Box::new(UnblacklistExpiredRefreshTokens::new()));

    job_runner.start();
}
