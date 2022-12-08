use std::time::Duration;

#[derive(Debug)]
pub enum JobError {}

pub struct Job {
    update_frequency: Duration,
    executor: Box<dyn Fn() -> Result<(), JobError>>,
}

impl Job {
    pub fn new<T>(update_frequency: Duration, executor: T) -> Self
    where
        T: Fn() -> Result<(), JobError> + 'static,
    {
        Self {
            update_frequency,
            executor: Box::new(executor),
        }
    }
}
