pub mod senders;
pub mod templates;

use lettre::message::Mailbox;

#[derive(Debug)]
pub enum EmailError {
    RelayConnectionFailed(String),
    InvalidDestination,
    InvalidMessage(lettre::error::Error),
    FailedToSend(lettre::transport::smtp::Error),
}

use async_trait::async_trait;
use std::fmt;

impl std::error::Error for EmailError {}

impl fmt::Display for EmailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmailError::RelayConnectionFailed(e) => {
                write!(f, "EmailError: Relay connection failed: {e}")
            }
            EmailError::InvalidDestination => write!(f, "EmailError: Invalid destination address"),
            EmailError::InvalidMessage(e) => write!(f, "EmailError: Invalid message {e}"),
            EmailError::FailedToSend(e) => write!(f, "EmailError: Failed to send: {e}"),
        }
    }
}

#[derive(Debug)]
pub struct EmailMessage<'a> {
    pub body: String,
    pub subject: &'a str,
    pub from: Mailbox,
    pub reply_to: Mailbox,
    pub destination: &'a str,
    pub is_html: bool,
}

#[async_trait]
pub trait SendEmail: Send + Sync {
    async fn send<'a>(&self, message: EmailMessage<'a>) -> Result<(), EmailError>;
}

pub type EmailSender = Box<dyn SendEmail>;
