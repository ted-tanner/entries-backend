#[macro_use]
extern crate lazy_static;

use flexi_logger::{
    Age, Cleanup, Criterion, Duplicate, FileSpec, LogSpecification, Logger, Naming, WriteMode,
};

mod env;
mod jobs;
mod runner;

use jobs::{ClearOtpAttemptsJob, ClearPasswordAttemptsJob, UnblacklistExpiredRefreshTokensJob};

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

    let mut job_runner = env::runner::JOB_RUNNER
        .lock()
        .expect("Job runner lock was poisioned");
    job_runner.register(Box::new(ClearOtpAttemptsJob::new()));
    job_runner.register(Box::new(ClearPasswordAttemptsJob::new()));
    job_runner.register(Box::new(UnblacklistExpiredRefreshTokensJob::new()));

    job_runner.start();
}
