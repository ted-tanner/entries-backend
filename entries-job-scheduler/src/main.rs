use entries_utils::db::create_db_thread_pool;
use flexi_logger::{Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, Naming, WriteMode};
use runner::JobRunner;
use std::time::Duration;
use zeroize::Zeroizing;

mod env;
mod jobs;
mod runner;

use jobs::{
    ClearExpiredBudgetInvitesJob, ClearExpiredOtpsJob, ClearOldUserDeletionRequestsJob,
    ClearUnverifiedUsersJob, DeleteUsersJob, UnblacklistExpiredTokensJob,
};

fn main() {
    let db_uri = Zeroizing::new(format!(
        "postgres://{}:{}@{}:{}/{}",
        env::CONF.db_username,
        env::CONF.db_password,
        env::CONF.db_hostname,
        env::CONF.db_port,
        env::CONF.db_name,
    ));

    let db_thread_pool = create_db_thread_pool(
        &db_uri,
        env::CONF.db_max_connections,
        env::CONF.db_idle_timeout,
    );

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(env::CONF.worker_threads)
        .max_blocking_threads(env::CONF.max_blocking_threads)
        .enable_all()
        .build()
        .expect("Failed to launch asynchronous runtime")
        .block_on(async move {
            Logger::try_with_str(&env::CONF.log_level)
                .expect(
                    "Invalid log level. Options: ERROR, WARN, INFO, DEBUG, TRACE. \
                     Example: `info, my::critical::module=trace`",
                )
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
                .expect("Failed to start logger");

            let mut job_runner = JobRunner::new(env::CONF.update_frequency, db_thread_pool.clone());

            job_runner
                .register(
                    Box::new(ClearExpiredBudgetInvitesJob::new(db_thread_pool.clone())),
                    env::CONF.clear_expired_budget_invites_job_frequency,
                )
                .await;

            job_runner
                .register(
                    Box::new(ClearExpiredOtpsJob::new(db_thread_pool.clone())),
                    env::CONF.clear_expired_otps_job_frequency,
                )
                .await;

            job_runner
                .register(
                    Box::new(ClearOldUserDeletionRequestsJob::new(db_thread_pool.clone())),
                    env::CONF.clear_old_user_deletion_requests_job_frequency,
                )
                .await;

            job_runner
                .register(
                    Box::new(ClearUnverifiedUsersJob::new(
                        Duration::from_secs(
                            env::CONF.clear_unverified_users_max_user_age_days * 86400,
                        ),
                        db_thread_pool.clone(),
                    )),
                    env::CONF.clear_unverified_users_job_frequency,
                )
                .await;

            job_runner
                .register(
                    Box::new(DeleteUsersJob::new(db_thread_pool.clone())),
                    env::CONF.delete_users_job_frequency,
                )
                .await;

            job_runner
                .register(
                    Box::new(UnblacklistExpiredTokensJob::new(db_thread_pool.clone())),
                    env::CONF.unblacklist_expired_tokens_job_frequency,
                )
                .await;

            job_runner.start().await;
        });

    unsafe {
        env::CONF.zeroize();
    }
}
