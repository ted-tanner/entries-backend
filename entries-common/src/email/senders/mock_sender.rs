use async_trait::async_trait;

use crate::email::{EmailError, EmailMessage, SendEmail};

#[derive(Default)]
pub struct MockSender {}

impl MockSender {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl SendEmail for MockSender {
    async fn send<'a>(&self, message: EmailMessage<'a>) -> Result<(), EmailError> {
        println!("\n\n{:#?}\n\n", message);
        Ok(())
    }
}
