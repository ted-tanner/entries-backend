#![allow(dead_code)]

use ring::hmac;
use serde::{Deserialize, Serialize};
use std::fmt;
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

#[derive(Clone, Copy, Debug)]
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

pub fn generate_otp(user_id: &Uuid, unix_timestamp: u64) -> Result<OneTimePasscode, OtpError> {
    let time_segment = unix_timestamp / (env::CONF.lifetimes.otp_lifetime_mins * 60);

    let contents = format!("{}:{}", user_id, time_segment);

    // The following uses the algorithm recommended by RFC4226
    // See https://datatracker.ietf.org/doc/html/rfc4226#section-5.3

    // Use of the HOTP requires the server to resist brute force attacks. RFC4226 recommends throttling.
    // See https://datatracker.ietf.org/doc/html/rfc4226#section-7.3

    // I intentionally use HMAC_SHA1 here by RFC4226's recommendation.
    let key = hmac::Key::new(
        hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        env::CONF.keys.otp_key.as_bytes(),
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

pub fn verify_otp(
    passcode: OneTimePasscode,
    user_id: &Uuid,
    unix_timestamp: u64,
) -> Result<bool, OtpError> {
    Ok(generate_otp(user_id, unix_timestamp)? == passcode)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_generate_otp_different_for_different_users() {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let user1_id = Uuid::new_v4();
        let user2_id = Uuid::new_v4();

        let user1_otp = generate_otp(&user1_id, current_time).unwrap();
        let user2_otp = generate_otp(&user2_id, current_time).unwrap();

        assert_ne!(user1_otp, user2_otp);
        assert_eq!(user1_otp, generate_otp(&user1_id, current_time).unwrap());
    }

    #[test]
    fn test_generate_otp_different_at_different_times() {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let user_id = Uuid::new_v4();
        let otp1 = generate_otp(&user_id, current_time).unwrap();
        let otp2 = generate_otp(
            &user_id,
            current_time + env::CONF.lifetimes.otp_lifetime_mins * 60,
        )
        .unwrap();

        assert_ne!(otp1, otp2);

        let time3 = current_time - (current_time % (env::CONF.lifetimes.otp_lifetime_mins * 60));
        let time4 = time3 + env::CONF.lifetimes.otp_lifetime_mins * 60;

        let otp3 = generate_otp(&user_id, time3).unwrap();
        let otp4 = generate_otp(&user_id, time4).unwrap();

        assert_ne!(otp3, otp4);
    }

    #[test]
    fn test_generate_otp_same_within_time_segment() {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let user_id = Uuid::new_v4();
        let time1 = current_time - (current_time % (env::CONF.lifetimes.otp_lifetime_mins * 60));
        let time2 = time1 + env::CONF.lifetimes.otp_lifetime_mins * 60 - 1;
        let otp1 = generate_otp(&user_id, time1).unwrap();
        let otp2 = generate_otp(&user_id, time2).unwrap();

        assert_eq!(otp1, otp2);
    }

    #[test]
    fn test_verify_otp() {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let user_id = Uuid::new_v4();
        let generate_time =
            current_time - (current_time % (env::CONF.lifetimes.otp_lifetime_mins * 60));
        let verify_time = generate_time + env::CONF.lifetimes.otp_lifetime_mins * 60 - 1;
        let otp = generate_otp(&user_id, generate_time).unwrap();

        assert!(verify_otp(otp, &user_id, verify_time).unwrap());
    }

    #[test]
    fn test_verify_opt_fails_if_otp_is_expired() {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let user_id = Uuid::new_v4();
        let generate_time =
            current_time - (current_time % (env::CONF.lifetimes.otp_lifetime_mins * 60));
        let verify_time = generate_time + env::CONF.lifetimes.otp_lifetime_mins * 60;
        let otp = generate_otp(&user_id, generate_time).unwrap();

        assert!(!verify_otp(otp, &user_id, verify_time).unwrap());
    }

    #[test]
    fn test_verify_opt_fails_if_otp_has_wrong_user_id() {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let user1_id = Uuid::new_v4();
        let user2_id = Uuid::new_v4();

        let otp1 = generate_otp(&user1_id, current_time).unwrap();
        let otp2 = generate_otp(&user2_id, current_time).unwrap();

        assert!(!verify_otp(otp1, &user2_id, current_time).unwrap());
        assert!(!verify_otp(otp2, &user1_id, current_time).unwrap());
    }
}
