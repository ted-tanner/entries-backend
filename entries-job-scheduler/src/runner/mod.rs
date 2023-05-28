use entries_utils::db::job_registry::Dao as JobRegistryDao;

use entries_utils::db::DbThreadPool;
use futures::future;
use std::time::{Duration, Instant, SystemTime};
use tokio::time;

use crate::jobs::Job;

struct JobContainer {
    job: Box<dyn Job>,
    run_frequency: Duration,
    last_run_time: SystemTime,
}

pub struct JobRunner {
    jobs: Vec<JobContainer>,
    update_frequency: Duration,
    db_thread_pool: DbThreadPool,
}

impl JobRunner {
    pub fn new(update_frequency: Duration, db_thread_pool: DbThreadPool) -> Self {
        Self {
            jobs: Vec::new(),
            update_frequency,
            db_thread_pool,
        }
    }

    pub async fn register(&mut self, job: Box<dyn Job>, run_frequency: Duration) {
        let job_name_ref = job.name();

        log::info!(
            "Registered job \"{}\" to run every {} seconds",
            job_name_ref,
            run_frequency.as_secs()
        );

        let mut dao = JobRegistryDao::new(&self.db_thread_pool);
        let last_run_time = tokio::task::spawn_blocking(move || {
            dao.get_job_last_run_timestamp(job_name_ref)
                .unwrap_or_else(|e| {
                    log::error!(
                        "Failed to get last run timestamp for job '{}': {}",
                        job_name_ref,
                        e
                    );
                    None
                })
        })
        .await
        .unwrap_or_else(|e| {
            log::error!("Failed to join Tokio task: {}", e);
            None
        });

        let job_container = JobContainer {
            job,
            run_frequency,
            last_run_time: last_run_time.unwrap_or(SystemTime::now()),
        };

        self.jobs.push(job_container);
    }

    pub async fn start(&mut self) -> ! {
        loop {
            let before = Instant::now();

            let mut job_names = Vec::with_capacity(self.jobs.len());
            let mut job_futures = Vec::with_capacity(self.jobs.len());
            let mut record_job_run_futures = Vec::with_capacity(self.jobs.len());

            for job_container in &mut self.jobs {
                let job = &mut job_container.job;

                let time_elapsed_since_last_run = SystemTime::now()
                    .duration_since(job_container.last_run_time)
                    .unwrap_or(Duration::from_nanos(0));
                let is_time_to_run = time_elapsed_since_last_run >= job_container.run_frequency;

                if is_time_to_run && job.is_ready() {
                    let name_ref = job.name();
                    log::info!("Executing job \"{}\"", name_ref);
                    job_names.push(name_ref);
                    job_futures.push(job.execute());

                    let mut dao = JobRegistryDao::new(&self.db_thread_pool);
                    let record_run_task = tokio::task::spawn_blocking(move || {
                        dao.set_job_last_run_timestamp(name_ref, SystemTime::now())
                    });

                    record_job_run_futures.push(record_run_task);
                }
            }

            let (job_results, recording_results) = future::join(
                future::join_all(job_futures),
                future::join_all(record_job_run_futures),
            )
            .await;

            for (i, result) in job_results.into_iter().enumerate() {
                if let Err(e) = result {
                    log::error!("{}", e);
                } else {
                    log::info!("Job \"{}\" finished successfully", job_names[i]);
                }
            }

            for result in recording_results.into_iter() {
                if let Err(e) = result {
                    log::error!("Error recording job run: {}", e);
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

        tokio::task::spawn(async move { job_runner.start().await });

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
