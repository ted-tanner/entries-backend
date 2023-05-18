pub mod senders;

#[derive(Debug)]
pub enum EmailError {
    RelayConnectionFailed(String),
    IncompleteEmail(&'static str),
    FailedToSend(String),
}

use async_trait::async_trait;
use std::fmt;

impl std::error::Error for EmailError {}

impl fmt::Display for EmailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmailError::RelayConnectionFailed(e) => write!(f, "EmailError: Relay connection failed: {e}"),
            EmailError::IncompleteEmail(e) => write!(f, "EmailError: Incomplete email: {e}"),
            EmailError::FailedToSend(e) => write!(f, "EmailError: Failed to send: {e}"),
        }
    }
}

#[async_trait]
pub trait EmailSender {
    async fn send(&self, body: &str, dest: &str) -> Result<(), EmailError>;
}

pub struct EmailBuilder<'a> {
    body: Option<&'a str>,
    dest: Option<&'a str>,
    sender: Option<Box<dyn EmailSender>>,
}

impl<'a> EmailBuilder<'a> {
    pub fn new() -> Self {
        Self {
            body: None,
            dest: None,
            sender: None,
        }
    }

    pub fn with_sender(sender: Box<dyn EmailSender>) -> Self {
        Self {
            body: None,
            dest: None,
            sender: Some(sender),
        }
    }

    pub fn set_body(&mut self, body: &'a str) {
        self.body = Some(body);
    }

    pub fn set_destination(&mut self, dest: &'a str) {
        self.dest = Some(dest);
    }

    pub fn set_sender(&mut self, sender: Box<dyn EmailSender>) {
        self.sender = Some(sender);
    }

    pub async fn send(&self) -> Result<(), EmailError> {
        let body = match self.body {
            Some(b) => b,
            None => return Err(EmailError::IncompleteEmail("Email is missing a body")),
        };

        let dest = match self.dest {
            Some(d) => d,
            None => {
                return Err(EmailError::IncompleteEmail(
                    "Email is missing a destination",
                ))
            }
        };

        let sender = match &self.sender {
            Some(s) => s,
            None => {
                return Err(EmailError::IncompleteEmail(
                    "An EmailSender must be specified for this email",
                ))
            }
        };

        sender.send(body, dest).await
    }
}
