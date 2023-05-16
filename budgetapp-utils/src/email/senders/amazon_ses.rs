use crate::email::{EmailSender, EmailError};

pub struct AmazonSes<'a> {
    smtp_username: &'a str,
    smtp_key: &'a [u8],
}

impl<'a> AmazonSes<'a> {
    pub fn with_credentials(smtp_username: &'a str, smtp_key: &'a [u8]) -> Self {
        AmazonSes {
            smtp_username,
            smtp_key,
        }
    }
}

impl<'a> EmailSender for AmazonSes<'a> {
    fn send(&self, body: &str, dest: &str) -> Result<(), EmailError> {
        // TODO
        Ok(())
    }
}
