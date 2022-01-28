pub mod asynchr;
pub mod synchr;

use std::fmt;

#[derive(Debug)]
pub enum RedisError {
    CommandFailed(Option<&'static str>),
}

impl std::error::Error for RedisError {}

impl fmt::Display for RedisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedisError::CommandFailed(msg) => format_err(f, "Redis command failed", msg),
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
