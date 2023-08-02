mod protobuf;
mod query;

pub use protobuf::*;
pub use query::*;

use uuid::Uuid;

#[derive(Debug)]
pub enum MessageError {
    InvalidUuid,
    MissingField,
}

impl std::error::Error for MessageError {}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageError::InvalidUuid => write!(f, "Invalid UUID"),
            MessageError::MissingField => write!(f, "Missing field"),
        }
    }
}

impl From<Uuid> for UuidV4 {
    fn from(uuid: Uuid) -> Self {
        UuidV4 {
            value: Vec::from(uuid.into_bytes()),
        }
    }
}

#[inline(always)]
pub fn uuid_from_msg(uuid: Option<UuidV4>) -> Result<Uuid, MessageError> {
    uuid.ok_or(MessageError::MissingField)?.try_into()
}

impl TryFrom<UuidV4> for Uuid {
    type Error = MessageError;

    fn try_from(uuid: UuidV4) -> Result<Self, Self::Error> {
        Ok(Uuid::from_bytes(
            uuid.value
                .try_into()
                .map_err(|_| MessageError::InvalidUuid)?,
        ))
    }
}

impl TryFrom<&UuidV4> for Uuid {
    type Error = MessageError;

    fn try_from(uuid: &UuidV4) -> Result<Self, Self::Error> {
        Ok(Uuid::from_bytes(
            uuid.value
                .as_slice()
                .try_into()
                .map_err(|_| MessageError::InvalidUuid)?,
        ))
    }
}
