use async_trait::async_trait;
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use lettre::transport::smtp::PoolConfig;
use lettre::transport::smtp::authentication::Credentials;
use std::time::Duration;

use crate::email::{EmailSender, EmailError};

#[derive(Clone)]
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
                    .idle_timeout(idle_timeout)
            )
            .build::<Tokio1Executor>();

        Ok(Self { smtp_thread_pool })
    }

    pub async fn test_connection(&self) -> Result<bool, EmailError> {
        match self.smtp_thread_pool.test_connection().await {
            Ok(b) => Ok(b),
            Err(e) => Err(EmailError::RelayConnectionFailed(e.to_string()))
        }
    }
}

#[async_trait]
impl EmailSender for AmazonSes {
    async fn send(&self, body: &str, dest: &str) -> Result<(), EmailError> {
        // TODO
        Ok(())
    }
}
