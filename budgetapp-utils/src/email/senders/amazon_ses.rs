use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::PoolConfig;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::time::Duration;

use crate::email::{EmailError, EmailMessage, EmailSender};

pub struct AmazonSes {
    smtp_thread_pool: AsyncSmtpTransport<Tokio1Executor>,
}

impl AmazonSes {
    pub fn with_credentials(
        smtp_username: &str,
        smtp_key: &str,
        address: &str,
        pool_max_size: u32,
        idle_timeout: Duration,
    ) -> Result<Self, EmailError> {
        let builder = match AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(address) {
            Ok(b) => b,
            Err(e) => return Err(EmailError::RelayConnectionFailed(e.to_string())),
        };

        let smtp_thread_pool = builder
            .credentials(Credentials::new(
                String::from(smtp_username),
                String::from(smtp_key),
            ))
            .pool_config(
                PoolConfig::new()
                    .max_size(pool_max_size)
                    .idle_timeout(idle_timeout),
            )
            .build::<Tokio1Executor>();

        Ok(Self { smtp_thread_pool })
    }

    pub async fn test_connection(&self) -> Result<bool, EmailError> {
        self.smtp_thread_pool
            .test_connection()
            .await
            .map_err(|e| EmailError::RelayConnectionFailed(e.to_string()))
    }
}

#[async_trait]
impl EmailSender for AmazonSes {
    async fn send<'a>(&self, message: EmailMessage<'a>) -> Result<(), EmailError> {
        let content_type = if message.is_html {
            ContentType::TEXT_HTML
        } else {
            ContentType::TEXT_PLAIN
        };

        let email = Message::builder()
            .from(message.from)
            .reply_to(message.reply_to)
            .to(message
                .destination
                .parse()
                .map_err(|_| EmailError::InvalidDestination)?)
            .subject(message.subject)
            .header(content_type)
            .body(message.body)
            .map_err(|e| EmailError::InvalidMessage(e))?;

        match self.smtp_thread_pool.send(email).await {
            Ok(_) => Ok(()),
            Err(e) => Err(EmailError::FailedToSend(e)),
        }
    }
}
