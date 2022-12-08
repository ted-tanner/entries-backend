use std::fmt;
use std::time::{Duration, SystemTime};

#[derive(Debug)]
pub enum JobError {
    DatabaseQueryFailure(diesel::result::Error),
    NotReady,
}

impl fmt::Display for JobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobError::DatabaseQueryFailure(e) => {
                write!(f, "JobError: Database Query Failed: {}", e)
            }
            JobError::NotReady => {
                write!(f, "JobError: Attempted execution before job was ready")
            }
        }
    }
}

pub struct Job {
    name: String,
    run_frequency: Duration,
    last_run_time: SystemTime,
    executor: Box<dyn Fn() -> Result<(), JobError> + Send + 'static>,
}

impl Job {
    pub fn new<T>(name: &str, run_frequency: Duration, executor: T) -> Self
    where
        T: Fn() -> Result<(), JobError> + Send + 'static,
    {
        Self {
            name: String::from(name),
            run_frequency,
            last_run_time: SystemTime::now(),
            executor: Box::new(executor),
        }
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn ready(&self) -> bool {
        SystemTime::now() > self.last_run_time + self.run_frequency
    }

    pub fn execute(&mut self) -> Result<(), JobError> {
        if self.ready() {
            let res = (*self.executor)();
            self.last_run_time = SystemTime::now();

            res
        } else {
            Err(JobError::NotReady)
        }
    }
}
