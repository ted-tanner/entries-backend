#[macro_use]
extern crate lazy_static;

use budgetapp_utils::db::job_registry::Dao as JobRegistryDao;

use budgetapp_utils::models::job_registry_item::JobRegistryItem;
use flexi_logger::{
    Age, Cleanup, Criterion, Duplicate, FileSpec, LogSpecification, Logger, Naming, WriteMode,
};
use std::time::{Duration, SystemTime};

mod env;
mod jobs;
mod runner;

use jobs::{
    ClearAuthorizationAttemptsJob, ClearOtpAttemptsJob, ClearUnverifiedUsersJob,
    ClearUserLookupAttemptsJob, DeleteUsersJob, UnblacklistExpiredTokensJob,
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
                record.module_path().unwrap_or("<unknown>"),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .use_utc()
        .start()
        .expect("Failed to starer");

    let mut registry_dao = JobRegistryDao::new(&env::db::DB_THREAD_POOL);
    let registry = registry_dao
        .get_all_jobs()
        .expect("Failed to obtain job registry");

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

            job_runner.register(Box::new(ClearAuthorizationAttemptsJob::new(
                Duration::from_secs(
                    env::CONF
                        .clear_authorization_attempts_job
                        .job_frequency_secs,
                ),
                Duration::from_secs(
                    env::CONF
                        .clear_authorization_attempts_job
                        .attempts_lifetime_mins
                        * 60,
                ),
                get_last_run_time(ClearAuthorizationAttemptsJob::name(), &registry),
                env::db::DB_THREAD_POOL.clone(),
            )));

            job_runner.register(Box::new(ClearOtpAttemptsJob::new(
                Duration::from_secs(env::CONF.clear_otp_attempts_job.job_frequency_secs),
                Duration::from_secs(env::CONF.clear_otp_attempts_job.attempts_lifetime_mins * 60),
                get_last_run_time(ClearAuthorizationAttemptsJob::name(), &registry),
                env::db::DB_THREAD_POOL.clone(),
            )));

            job_runner.register(Box::new(ClearUnverifiedUsersJob::new(
                Duration::from_secs(env::CONF.clear_unverified_users_job.job_frequency_secs),
                Duration::from_secs(
                    env::CONF
                        .clear_unverified_users_job
                        .max_unverified_user_age_days
                        * 24
                        * 60
                        * 60,
                ),
                get_last_run_time(ClearUnverifiedUsersJob::name(), &registry),
                env::db::DB_THREAD_POOL.clone(),
            )));

            job_runner.register(Box::new(ClearUserLookupAttemptsJob::new(
                Duration::from_secs(env::CONF.clear_user_lookup_attempts_job.job_frequency_secs),
                Duration::from_secs(
                    env::CONF
                        .clear_user_lookup_attempts_job
                        .attempts_lifetime_mins
                        * 60,
                ),
                get_last_run_time(ClearUserLookupAttemptsJob::name(), &registry),
                env::db::DB_THREAD_POOL.clone(),
            )));

            job_runner.register(Box::new(DeleteUsersJob::new(
                Duration::from_secs(env::CONF.delete_users_job.job_frequency_secs),
                get_last_run_time(DeleteUsersJob::name(), &registry),
                env::db::DB_THREAD_POOL.clone(),
            )));

            job_runner.register(Box::new(UnblacklistExpiredTokensJob::new(
                Duration::from_secs(env::CONF.unblacklist_expired_tokens_job.job_frequency_secs),
                get_last_run_time(UnblacklistExpiredTokensJob::name(), &registry),
                env::db::DB_THREAD_POOL.clone(),
            )));

            job_runner.start().await;
        });
}

#[inline]
fn get_last_run_time(job_name: &str, registry: &[JobRegistryItem]) -> SystemTime {
    if let Some(t) = registry.iter().find(|&t| t.job_name == job_name) {
        t.last_run_timestamp
    } else {
        SystemTime::now()
    }
}
