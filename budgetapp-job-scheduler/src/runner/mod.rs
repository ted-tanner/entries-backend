use futures::future;
use std::time::{Duration, Instant};
use tokio::time;

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

    pub async fn start(&mut self) -> ! {
        loop {
            let before = Instant::now();

            let mut job_names = Vec::with_capacity(self.jobs.len());
            let mut job_futures = Vec::with_capacity(self.jobs.len());

            for job in &mut self.jobs {
                if job.ready() {
                    log::info!("Executing job \"{}\"", job.name());
                    job_names.push(job.name());
                    job_futures.push(job.execute());
                }
            }

            let results = future::join_all(job_futures).await;

            for (i, result) in results.into_iter().enumerate() {
                if let Err(e) = result {
                    log::error!("{}", e);
                } else {
                    log::info!("Job \"{}\" finished successfully", job_names[i]);
                }
            }

            let after = Instant::now();
            let delta = after - before;

            if delta < self.update_frequency {
                time::sleep(self.update_frequency - delta).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::time::Duration;

    use crate::jobs::tests::MockJob;

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

    #[tokio::test]
    async fn test_start() {
        let mut job_runner = JobRunner::new(Duration::from_micros(500));
        let job1 = MockJob::new(Duration::from_millis(10));
        let job2 = MockJob::new(Duration::from_millis(15));

        let job1_run_count = Arc::clone(&job1.runs);
        let job2_run_count = Arc::clone(&job2.runs);

        job_runner.register(Box::new(job1));
        job_runner.register(Box::new(job2));

        assert_eq!(*job1_run_count.lock().unwrap(), 0);
        assert_eq!(*job2_run_count.lock().unwrap(), 0);

        tokio::task::spawn(async move {
            job_runner.start().await
        });

        time::sleep(Duration::from_millis(12)).await;
        assert_eq!(*job1_run_count.lock().unwrap(), 1);
        assert_eq!(*job2_run_count.lock().unwrap(), 0);

        time::sleep(Duration::from_millis(5)).await;
        assert_eq!(*job1_run_count.lock().unwrap(), 1);
        assert_eq!(*job2_run_count.lock().unwrap(), 1);

        time::sleep(Duration::from_millis(5)).await;
        assert_eq!(*job1_run_count.lock().unwrap(), 2);
        assert_eq!(*job2_run_count.lock().unwrap(), 1);
    }
}
