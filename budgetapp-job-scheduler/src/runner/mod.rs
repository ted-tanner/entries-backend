use std::thread;
use std::time::{Duration, Instant};

use crate::jobs::Job;

pub struct JobRunner {
    jobs: Vec<Box<dyn Job>>,
    update_frequency: Duration,
}

impl JobRunner {
    pub fn new(update_frequency: Duration) -> Self {
        Self {
            jobs: Vec::new(),
            update_frequency,
        }
    }

    pub fn register(&mut self, job: Box<dyn Job>) {
        log::info!(
            "Registered job \"{}\" to run every {} seconds",
            job.name(),
            job.run_frequency().as_secs()
        );
        self.jobs.push(job);
    }

    pub fn start(&mut self) -> ! {
        loop {
            let before = Instant::now();

            for job in &mut self.jobs {
                if job.ready() {
                    log::info!("Executing job \"{}\"", job.name());

                    let res = job.execute();

                    if let Err(e) = res {
                        log::error!("{}", e);
                    } else {
                        log::info!("Job \"{}\" finished successfully", job.name());
                    }
                }
            }

            let after = Instant::now();
            let delta = after - before;

            if delta < self.update_frequency {
                thread::sleep(self.update_frequency - delta);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::jobs::{Job, JobError};

    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    struct MockJob {
        pub last_run_time: SystemTime,
        pub run_frequency: Duration,
        pub runs: Arc<Mutex<usize>>,
    }

    impl MockJob {
        pub fn new(run_frequency: Duration) -> Self {
            Self {
                last_run_time: SystemTime::now(),
                run_frequency,
                runs: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl Job for MockJob {
        fn name(&self) -> &'static str {
            "Mock"
        }

        fn run_frequency(&self) -> Duration {
            self.run_frequency
        }

        fn last_run_time(&self) -> SystemTime {
            self.last_run_time
        }

        fn set_last_run_time(&mut self, time: SystemTime) {
            self.last_run_time = time;
        }

        fn run_handler_func(&mut self) -> Result<(), JobError> {
            *self.runs.lock().unwrap() += 1;
            Ok(())
        }
    }

    #[test]
    fn test_register() {
        let mut job_runner = JobRunner::new(Duration::from_micros(200));
        assert_eq!(job_runner.update_frequency, Duration::from_micros(200));
        assert!(job_runner.jobs.is_empty());

        let mock_job1 = MockJob::new(Duration::from_millis(1));
        let mock_job2 = MockJob::new(Duration::from_millis(3));

        job_runner.register(Box::new(mock_job1));
        assert_eq!(job_runner.jobs.len(), 1);

        job_runner.register(Box::new(mock_job2));
        assert_eq!(job_runner.jobs.len(), 2);
    }

    #[test]
    fn test_start() {
        let mut job_runner = JobRunner::new(Duration::from_micros(500));
        let job1 = MockJob::new(Duration::from_millis(10));
        let job2 = MockJob::new(Duration::from_millis(15));

        let job1_run_count = Arc::clone(&job1.runs);
        let job2_run_count = Arc::clone(&job2.runs);

        job_runner.register(Box::new(job1));
        job_runner.register(Box::new(job2));

        assert_eq!(*job1_run_count.lock().unwrap(), 0);
        assert_eq!(*job2_run_count.lock().unwrap(), 0);

        thread::spawn(move || {
            job_runner.start();
        });

        thread::sleep(Duration::from_millis(11));
        assert_eq!(*job1_run_count.lock().unwrap(), 1);
        assert_eq!(*job2_run_count.lock().unwrap(), 0);

        thread::sleep(Duration::from_millis(5));
        assert_eq!(*job1_run_count.lock().unwrap(), 1);
        assert_eq!(*job2_run_count.lock().unwrap(), 1);

        thread::sleep(Duration::from_millis(5));
        assert_eq!(*job1_run_count.lock().unwrap(), 2);
        assert_eq!(*job2_run_count.lock().unwrap(), 1);
    }
}
