#[macro_use]
extern crate lazy_static;

use flexi_logger::{
    Age, Cleanup, Criterion, Duplicate, FileSpec, LogSpecification, Logger, Naming, WriteMode,
};
use runner::JobRunner;
use std::time::Duration;

mod env;
mod jobs;
mod runner;

use jobs::{
    ClearExpiredBudgetInvitesJob, ClearExpiredOtpsJob, ClearOldUserDeletionRequestsJob,
    ClearThrottleTableJob, ClearUnverifiedUsersJob, DeleteUsersJob, UnblacklistExpiredTokensJob,
};

fn main() {
    let mut conf_file_path: Option<String> = None;
    let mut args = std::env::args();

    // Eat the first argument, which is the relative path to the executable
    args.next();

    while let Some(arg) = args.next() {
        match arg.to_lowercase().as_str() {
            "--config" => {
                conf_file_path = {
                    let next_arg = args.next();

                    match next_arg {
                        Some(p) => Some(p),
                        None => {
                            eprintln!(
                                "ERROR: --config option specified but no config file path was given",
                            );
                            std::process::exit(1);
                        }
                    }
                };

                continue;
            }
            a => {
                eprintln!("ERROR: Invalid argument: {}", &a);
                std::process::exit(1);
            }
        }
    }

    env::initialize(&conf_file_path.unwrap_or(String::from("conf/jobs-conf.toml")));

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
            let mut job_runner = JobRunner::new(
                Duration::from_secs(env::CONF.runner.update_frequency_secs),
                env::db::DB_THREAD_POOL.clone(),
            );

            job_runner
                .register(
                    Box::new(ClearExpiredBudgetInvitesJob::new(
                        env::db::DB_THREAD_POOL.clone(),
                    )),
                    Duration::from_secs(
                        env::CONF
                            .clear_expired_budget_invites_job
                            .job_frequency_secs,
                    ),
                )
                .await;

            job_runner
                .register(
                    Box::new(ClearExpiredOtpsJob::new(env::db::DB_THREAD_POOL.clone())),
                    Duration::from_secs(env::CONF.clear_expired_otps_job.job_frequency_secs),
                )
                .await;

            job_runner
                .register(
                    Box::new(ClearOldUserDeletionRequestsJob::new(
                        env::db::DB_THREAD_POOL.clone(),
                    )),
                    Duration::from_secs(
                        env::CONF
                            .clear_old_user_deletion_requests_job
                            .job_frequency_secs,
                    ),
                )
                .await;

            job_runner
                .register(
                    Box::new(ClearThrottleTableJob::new(env::db::DB_THREAD_POOL.clone())),
                    Duration::from_secs(env::CONF.clear_throttle_table_job.job_frequency_secs),
                )
                .await;

            job_runner
                .register(
                    Box::new(ClearUnverifiedUsersJob::new(
                        Duration::from_secs(
                            env::CONF
                                .clear_unverified_users_job
                                .max_unverified_user_age_days
                                * 24
                                * 60
                                * 60,
                        ),
                        env::db::DB_THREAD_POOL.clone(),
                    )),
                    Duration::from_secs(env::CONF.clear_unverified_users_job.job_frequency_secs),
                )
                .await;

            job_runner
                .register(
                    Box::new(DeleteUsersJob::new(env::db::DB_THREAD_POOL.clone())),
                    Duration::from_secs(env::CONF.delete_users_job.job_frequency_secs),
                )
                .await;

            job_runner
                .register(
                    Box::new(UnblacklistExpiredTokensJob::new(
                        env::db::DB_THREAD_POOL.clone(),
                    )),
                    Duration::from_secs(
                        env::CONF.unblacklist_expired_tokens_job.job_frequency_secs,
                    ),
                )
                .await;

            job_runner.start().await;
        });
}
