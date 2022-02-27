use log::{error, info, warn};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::definitions::AtomicMutex;

type CronJob = (
    Box<dyn Fn() -> Result<(), CronJobError> + Send + 'static>,
    String,
);

#[derive(Debug)]
pub enum CronJobError {
    JobFailure(Option<&'static str>),
}

impl std::error::Error for CronJobError {}

impl fmt::Display for CronJobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CronJobError::JobFailure(msg) => format_err(f, "Cron job failure", msg),
        }
    }
}

fn format_err(
    f: &mut fmt::Formatter<'_>,
    error_txt: &str,
    msg: &Option<&'static str>,
) -> fmt::Result {
    write!(
        f,
        "{}{}",
        error_txt,
        if msg.is_some() {
            format!(": {}", msg.as_ref().unwrap())
        } else {
            String::new()
        }
    )
}

pub struct Runner {
    jobs: AtomicMutex<Vec<CronJob>>,
    granularity: Duration,
    stop_flag: Arc<AtomicBool>,
}

impl Runner {
    pub fn with_granularity(duration: Duration) -> Self {
        let mut new_runner = Self {
            jobs: Arc::new(Mutex::new(Vec::new())),
            granularity: duration,
            stop_flag: Arc::new(AtomicBool::new(false)),
        };

        new_runner.start();

        new_runner
    }

    pub fn add_job<F>(&self, job: F, job_name: String)
    where
        F: Fn() -> Result<(), CronJobError> + Send + 'static,
    {
        self.jobs
            .lock()
            .expect("Tried to aquire poisoned mutex")
            .push((Box::new(job), job_name));
    }

    pub fn start(&mut self) {
        self.stop_flag.store(false, Ordering::SeqCst);

        let sleep_duration = self.granularity;
        let stop_flag = self.stop_flag.clone();
        let jobs = self.jobs.clone();

        let thread_spawn_res = thread::Builder::new()
            .name(format!(
                "cron-job-runner-{}-{}",
                sleep_duration.as_millis(),
                rand::random::<u32>()
            ))
            .spawn(move || {
                let mut time_elapsed_running_job = Duration::new(0, 0);

                loop {
                    if time_elapsed_running_job < sleep_duration {
                        thread::sleep(sleep_duration - time_elapsed_running_job);
                    } else {
                        const MILLIS_IN_10_HOURS: u128 = 36_000_000;
                        const MILLIS_IN_30_SECS: u128 = 30_000;

                        const SECS_IN_ONE_HOUR: u64 = 3600;

                        let elapsed_time_optimal_units = if time_elapsed_running_job.as_millis() >= MILLIS_IN_10_HOURS {
                            format!("{}h", time_elapsed_running_job.as_secs() * SECS_IN_ONE_HOUR)
                        } else if time_elapsed_running_job.as_millis() >= MILLIS_IN_30_SECS {
                            format!("{}s", time_elapsed_running_job.as_secs())
                        } else {
                            format!("{}ms", time_elapsed_running_job.as_millis())
                        };

                        let allowed_time_optimal_units = if sleep_duration.as_millis() >= MILLIS_IN_10_HOURS {
                            format!("{}h", sleep_duration.as_secs() * SECS_IN_ONE_HOUR)
                        } else if sleep_duration.as_millis() >= MILLIS_IN_30_SECS {
                            format!("{}s", sleep_duration.as_secs())
                        } else {
                            format!("{}ms", sleep_duration.as_millis())
                        };

                        warn!("Runner wasn't able to complete job(s) before the next scheduled run. Job(s) took {} but should be run every {}.", elapsed_time_optimal_units, allowed_time_optimal_units);
                    }

                    let start_time = Instant::now();

                    if stop_flag.load(Ordering::SeqCst) {
                        break;
                    }

                    let jobs = jobs.lock().expect("Tried to aquire poisoned mutex");

                    for job in &*jobs {
                        info!("Running cron job: '{}'", &job.1);

                        match job.0() {
                            Ok(_) => info!("Cron job completed successfully: '{}'", &job.1),
                            Err(e) => error!("Cron job failed: '{}': {e}", &job.1),
                        }
                    }

                    time_elapsed_running_job = Instant::now() - start_time;
                }
            });

        if thread_spawn_res.is_err() {
            error!("Failed to spawn cron job runner");
        }
    }

    #[allow(dead_code)]
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    #[actix_rt::test]
    async fn test_cron_job() {
        let state = Arc::new(Mutex::new(0u8));

        let state_for_closure = state.clone();

        let mut job_runner = Runner::with_granularity(Duration::from_millis(8));
        job_runner.add_job(
            move || {
                let mut state = state_for_closure.lock().unwrap();
                *state += 1;

                Ok(())
            },
            String::from("Test modify state"),
        );

        thread::sleep(Duration::from_millis(20));
        job_runner.stop();

        let state_mutex = state.lock().unwrap();
        let curr_state = *state_mutex;
        drop(state_mutex);

        assert_eq!(curr_state, 2);

        thread::sleep(Duration::from_millis(12));

        let state_mutex = state.lock().unwrap();
        let curr_state = *state_mutex;
        drop(state_mutex);

        assert_eq!(curr_state, 2);

        job_runner.start();
        thread::sleep(Duration::from_millis(12));
        job_runner.stop();

        let state_mutex = state.lock().unwrap();
        let curr_state = *state_mutex;
        drop(state_mutex);

        assert_eq!(curr_state, 3);
    }
}
