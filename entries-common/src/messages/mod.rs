mod protobuf;
mod query;

use std::time::{Duration, SystemTime};

pub use protobuf::*;
pub use query::*;

use uuid::Uuid as NonMessageUuid;

#[derive(Debug)]
pub enum MessageError {
    InvalidUuid,
    InvalidTimestamp,
    MissingField,
}

impl std::error::Error for MessageError {}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageError::InvalidUuid => write!(f, "Invalid UUID"),
            MessageError::InvalidTimestamp => write!(f, "Invalid timestamp"),
            MessageError::MissingField => write!(f, "Missing field"),
        }
    }
}

impl From<&NonMessageUuid> for Uuid {
    fn from(uuid: &NonMessageUuid) -> Self {
        Uuid {
            value: Vec::from(uuid.into_bytes()),
        }
    }
}

impl From<NonMessageUuid> for Uuid {
    fn from(uuid: NonMessageUuid) -> Self {
        (&uuid).into()
    }
}

impl TryFrom<Uuid> for NonMessageUuid {
    type Error = MessageError;

    fn try_from(uuid: Uuid) -> Result<Self, Self::Error> {
        (&uuid).try_into()
    }
}

impl TryFrom<&Uuid> for NonMessageUuid {
    type Error = MessageError;

    fn try_from(uuid: &Uuid) -> Result<Self, Self::Error> {
        Ok(NonMessageUuid::from_bytes(
            uuid.value
                .as_slice()
                .try_into()
                .map_err(|_| MessageError::InvalidUuid)?,
        ))
    }
}

impl TryFrom<SystemTime> for Timestamp {
    type Error = MessageError;

    fn try_from(timestamp: SystemTime) -> Result<Self, Self::Error> {
        let since_unix_epoch = timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| MessageError::InvalidTimestamp)?;

        Ok(Timestamp {
            secs: since_unix_epoch.as_secs(),
            nanos: since_unix_epoch.subsec_nanos(),
        })
    }
}

impl From<&Timestamp> for SystemTime {
    fn from(timestamp: &Timestamp) -> Self {
        SystemTime::UNIX_EPOCH
            + Duration::from_secs(timestamp.secs)
            + Duration::from_nanos(timestamp.nanos.into())
    }
}
