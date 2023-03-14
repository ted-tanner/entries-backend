use hmac::{self, Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

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
                "OtpError: An error occured while generating one-time passcode: {msg}"
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

pub fn generate_otp(
    user_id: Uuid,
    timestamp: SystemTime,
    lifetime: Duration,
    secret_key: &[u8; 64],
) -> Result<OneTimePasscode, OtpError> {
    let time_segment = timestamp
        .duration_since(UNIX_EPOCH)
        .expect("Failed to fetch system time")
        .as_secs()
        / lifetime.as_secs();
    let contents = format!("{user_id}:{time_segment}");

    // The following uses the algorithm recommended by RFC4226
    // See https://datatracker.ietf.org/doc/html/rfc4226#section-5.3

    // Use of the HOTP requires the server to resist brute force attacks. RFC4226 recommends throttling.
    // See https://datatracker.ietf.org/doc/html/rfc4226#section-7.3

    // I intentionally use HMAC_SHA1 here by RFC4226's recommendation.
    let mut mac = match Hmac::<Sha1>::new_from_slice(secret_key) {
        Ok(m) => m,
        Err(_) => {
            return Err(OtpError::Error(String::from(
                "Failed to initalize key for HMAC",
            )))
        }
    };
    mac.update(contents.as_bytes());

    let hash = mac.finalize().into_bytes();

    let offset = hash[19] as usize & 0xf;
    let bin_code = (hash[offset] as u32 & 0x7f) << 24
        | (hash[offset + 1] as u32 & 0xff) << 16
        | (hash[offset + 2] as u32 & 0xff) << 8
        | (hash[offset + 3] as u32 & 0xff);

    let otp = bin_code % (10u32.pow(8));

    Ok(OneTimePasscode(otp))
}

pub fn verify_otp(
    passcode: OneTimePasscode,
    user_id: Uuid,
    timestamp: SystemTime,
    lifetime: Duration,
    secret_key: &[u8; 64],
) -> Result<bool, OtpError> {
    Ok(generate_otp(user_id, timestamp, lifetime, secret_key)? == passcode)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_generate_otp_different_for_different_users() {
        let user1_id = Uuid::new_v4();
        let user2_id = Uuid::new_v4();

        let user1_otp = generate_otp(
            user1_id,
            SystemTime::now(),
            Duration::from_secs(5),
            &[0u8; 64],
        )
        .unwrap();
        let user2_otp = generate_otp(
            user2_id,
            SystemTime::now(),
            Duration::from_secs(5),
            &[0u8; 64],
        )
        .unwrap();

        assert_ne!(user1_otp, user2_otp);
        assert_eq!(
            user1_otp,
            generate_otp(
                user1_id,
                SystemTime::now(),
                Duration::from_secs(5),
                &[0u8; 64]
            )
            .unwrap()
        );
    }

    #[test]
    fn test_generate_otp_different_at_different_times() {
        let user_id = Uuid::new_v4();
        let otp1 = generate_otp(
            user_id,
            SystemTime::now(),
            Duration::from_secs(5),
            &[0u8; 64],
        )
        .unwrap();
        let otp2 = generate_otp(
            user_id,
            SystemTime::now() + Duration::from_secs(10000),
            Duration::from_secs(5),
            &[0u8; 64],
        )
        .unwrap();

        assert_ne!(otp1, otp2);

        let time3 = SystemTime::now()
            - Duration::from_secs(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    % 5,
            );
        let time4 = time3 + Duration::from_secs(5);

        let otp3 = generate_otp(user_id, time3, Duration::from_secs(5), &[0u8; 64]).unwrap();
        let otp4 = generate_otp(user_id, time4, Duration::from_secs(5), &[0u8; 64]).unwrap();

        assert_ne!(otp3, otp4);
    }

    #[test]
    fn test_generate_otp_same_within_time_segment() {
        let user_id = Uuid::new_v4();
        let time1 = SystemTime::now()
            - Duration::from_secs(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    % 5,
            );
        let time2 = time1 + Duration::from_secs(5 - 1);
        let otp1 = generate_otp(user_id, time1, Duration::from_secs(5), &[0u8; 64]).unwrap();
        let otp2 = generate_otp(user_id, time2, Duration::from_secs(5), &[0u8; 64]).unwrap();

        assert_eq!(otp1, otp2);
    }

    #[test]
    fn test_verify_otp() {
        let user_id = Uuid::new_v4();
        let generate_time = SystemTime::now()
            - Duration::from_secs(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    % 5,
            );
        let verify_time = generate_time + Duration::from_secs(4);
        let otp = generate_otp(user_id, generate_time, Duration::from_secs(5), &[0u8; 64]).unwrap();

        assert!(verify_otp(
            otp,
            user_id,
            verify_time,
            Duration::from_secs(5),
            &[0u8; 64]
        )
        .unwrap());
    }

    #[test]
    fn test_verify_opt_fails_if_otp_is_expired() {
        let user_id = Uuid::new_v4();
        let generate_time = SystemTime::now()
            - Duration::from_secs(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    % 5,
            );
        let verify_time = generate_time + Duration::from_secs(5);
        let otp = generate_otp(user_id, generate_time, Duration::from_secs(5), &[0u8; 64]).unwrap();

        assert!(!verify_otp(
            otp,
            user_id,
            verify_time,
            Duration::from_secs(5),
            &[0u8; 64]
        )
        .unwrap());
    }

    #[test]
    fn test_verify_opt_fails_if_otp_has_wrong_user_id() {
        let user1_id = Uuid::new_v4();
        let user2_id = Uuid::new_v4();

        let otp1 = generate_otp(
            user1_id,
            SystemTime::now(),
            Duration::from_secs(5),
            &[0u8; 64],
        )
        .unwrap();
        let otp2 = generate_otp(
            user2_id,
            SystemTime::now(),
            Duration::from_secs(5),
            &[0u8; 64],
        )
        .unwrap();

        assert!(!verify_otp(
            otp1,
            user2_id,
            SystemTime::now(),
            Duration::from_secs(5),
            &[0u8; 64],
        )
        .unwrap());
        assert!(!verify_otp(
            otp2,
            user1_id,
            SystemTime::now(),
            Duration::from_secs(5),
            &[0u8; 64],
        )
        .unwrap());
    }
}
