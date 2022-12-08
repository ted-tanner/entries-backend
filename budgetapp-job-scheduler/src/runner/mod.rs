use std::thread;
use std::time::Duration;

use crate::jobs::Job;

pub struct JobRunner {
    jobs: Vec<Job>,
    update_frequency_secs: Duration,
}

impl JobRunner {
    pub fn new(update_frequency_secs: Duration) -> Self {
        Self {
            jobs: Vec::new(),
            update_frequency_secs,
        }
    }

    pub fn register(&mut self, job: Job) {
        self.jobs.push(job);
    }

    pub fn start(&mut self) -> ! {
        loop {
            thread::sleep(self.update_frequency_secs);

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
        }
    }
}
