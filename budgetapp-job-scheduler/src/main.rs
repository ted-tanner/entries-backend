#[macro_use]
extern crate lazy_static;

use flexi_logger::{
    Age, Cleanup, Criterion, Duplicate, FileSpec, LogSpecification, Logger, Naming, WriteMode,
};
use std::time::Duration;

mod env;
mod jobs;
mod runner;

use jobs::{
    ClearOtpAttemptsJob, ClearPasswordAttemptsJob, DeleteUsersJob,
    UnblacklistExpiredRefreshTokensJob,
};

fn main() {
    Logger::with(LogSpecification::info())
        .log_to_file(FileSpec::default().directory("./logs"))
        .rotate(
            Criterion::Age(Age::Day),
            Naming::Timestamps,
            Cleanup::KeepLogAndCompressedFiles(60, 365),
        )
        .cleanup_in_background_thread(true)
        .duplicate_to_stdout(Duplicate::All)
        .write_mode(WriteMode::BufferAndFlush)
        .format(|writer, now, record| {
            write!(
                writer,
                "{:5} | {} | {}:{} | {}",
                record.level(),
                now.format("%Y-%m-%dT%H:%M:%S%.6fZ"),
                record.file().unwrap_or("<unknown>"),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .use_utc()
        .start()
        .expect("Failed to start logger");

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(
            env::CONF
                .runner
                .worker_threads
                .unwrap_or(num_cpus::get() + 1),
        )
        .max_blocking_threads(env::CONF.runner.max_blocking_threads.unwrap_or(512))
        .enable_all()
        .build()
        .expect("Failed to launch asynchronous runtime")
        .block_on(async move {
            let mut job_runner = env::runner::JOB_RUNNER.lock().await;

            job_runner.register(Box::new(ClearOtpAttemptsJob::new(
                Duration::from_secs(env::CONF.clear_otp_attempts_job.job_frequency_secs),
                Duration::from_secs(env::CONF.clear_otp_attempts_job.attempts_lifetime_mins * 60),
                env::db::DB_THREAD_POOL.clone(),
            )));

            job_runner.register(Box::new(ClearPasswordAttemptsJob::new(
                Duration::from_secs(env::CONF.clear_otp_attempts_job.job_frequency_secs),
                Duration::from_secs(
                    env::CONF.clear_password_attempts_job.attempts_lifetime_mins * 60,
                ),
                env::db::DB_THREAD_POOL.clone(),
            )));

            job_runner.register(Box::new(DeleteUsersJob::new(
                Duration::from_secs(env::CONF.delete_users_job.job_frequency_secs),
                env::db::DB_THREAD_POOL.clone(),
            )));

            job_runner.register(Box::new(UnblacklistExpiredRefreshTokensJob::new(
                Duration::from_secs(
                    env::CONF
                        .unblacklist_expired_refresh_tokens_job
                        .job_frequency_secs,
                ),
                env::db::DB_THREAD_POOL.clone(),
            )));

            job_runner.start().await;
        });
}
