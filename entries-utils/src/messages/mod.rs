mod protobuf;

pub use protobuf::*;

use uuid::Uuid;

#[derive(Debug)]
pub enum MessageError {
    InvalidUuid,
}

impl std::error::Error for MessageError {}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageError::InvalidUuid => write!(f, "Invalid UUID. A UUID should be 16 bytes long."),
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

impl TryFrom<UuidV4> for Uuid {
    type Error = MessageError;

    fn try_from(uuid: UuidV4) -> Result<Self, Self::Error> {
        const UUID_LEN_BYTES: usize = 16;

        if uuid.value.len() != UUID_LEN_BYTES {
            return Err(MessageError::InvalidUuid);
        }

        let uuid_bytes: [u8; 16] = unsafe {
            uuid.value
                .get_unchecked(..UUID_LEN_BYTES)
                .try_into()
                .unwrap_unchecked()
        };

        Ok(Uuid::from_bytes(uuid_bytes))
    }
}
