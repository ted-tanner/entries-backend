use ring::hmac;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::env;

#[derive(Debug, Serialize, Deserialize)]
pub enum OtpError {
    Unauthorized,
    ImproperlyFormatted,
    Error(String),
}

impl std::error::Error for OtpError {}

impl fmt::Display for OtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OtpError::Unauthorized => write!(f, "OtpError: Invalid or expired sign-in token"),
            OtpError::ImproperlyFormatted => {
                write!(f, "OtpError: Invalid or expired sign-in token")
            }
            OtpError::Error(msg) => write!(
                f,
                "OtpError: An error occured while generating one-time passcode: {}",
                msg
            ),
        }
    }
}

#[derive(Debug)]
pub struct OneTimePasscode(u32);

impl fmt::Display for OneTimePasscode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:0>4} {:0>4}", self.0 / 10000, self.0 % 10000)
    }
}

impl From<u32> for OneTimePasscode {
    fn from(value: u32) -> Self {
        OneTimePasscode(value)
    }
}

impl TryFrom<String> for OneTimePasscode {
    type Error = OtpError;

    fn try_from(mut value: String) -> Result<Self, OtpError> {
        value.retain(|c| !c.is_whitespace());

        if value.len() != 8 {
            return Err(OtpError::ImproperlyFormatted);
        }

        let code = match value.parse() {
            Ok(u) => u,
            Err(_) => return Err(OtpError::ImproperlyFormatted),
        };

        Ok(OneTimePasscode(code))
    }
}

impl PartialEq for OneTimePasscode {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

pub fn generate_otp(user_id: &Uuid) -> Result<OneTimePasscode, OtpError> {
    let time_segment = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(t) => t,
        Err(_) => {
            return Err(OtpError::Error(String::from(
                "Failed to access system time",
            )))
        }
    }
    .as_secs();
    let time_segment = time_segment / *env::otp::OTP_LIFETIME_SECS;

    let contents = format!("{}:{}", user_id, time_segment);

    // The following uses the algorithm recommended by RFC4226
    // See https://datatracker.ietf.org/doc/html/rfc4226#section-5.3

    // Use of the HOTP requires the server to resist brute force attacks. RFC4226 recommends throttling.
    // See https://datatracker.ietf.org/doc/html/rfc4226#section-7.3

    // I intentionally use HMAC_SHA1 here by RFC4226's recommendation.
    let key = hmac::Key::new(
        hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        &*env::otp::OTP_SECRET_KEY,
    );
    let hash = hmac::sign(&key, contents.as_bytes());

    let offset = hash.as_ref()[19] as usize & 0xf;
    let bin_code = (hash.as_ref()[offset] as u32 & 0x7f) << 24
        | (hash.as_ref()[offset + 1] as u32 & 0xff) << 16
        | (hash.as_ref()[offset + 2] as u32 & 0xff) << 8
        | (hash.as_ref()[offset + 3] as u32 & 0xff);

    let otp = bin_code % (10u32.pow(8));

    Ok(OneTimePasscode(otp))
}

pub fn verify_otp(passcode: OneTimePasscode, user_id: &Uuid) -> Result<bool, OtpError> {
    Ok(generate_otp(user_id)? == passcode)
}
