use rand::distributions::Alphanumeric;
use rand::Rng;

use crate::threadrand::SecureRng;

pub struct Otp {}

impl Otp {
    pub fn generate(length: usize) -> String {
        SecureRng
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(|c| char::from(c).to_ascii_uppercase())
            .collect()
    }

    pub fn are_equal(given: &str, saved: &str) -> bool {
        let given = given.as_bytes();
        let saved = saved.as_bytes();

        if given.len() != saved.len() {
            return false;
        }

        let mut otps_dont_match = 0u8;

        // Do bitwise comparison to prevent timing attacks
        for (i, saved_char) in saved.iter().enumerate() {
            unsafe {
                otps_dont_match |= saved_char ^ given.get_unchecked(i);
            }
        }

        otps_dont_match == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_verify() {
        let otp = Otp::generate(8);
        assert!(Otp::are_equal(&otp, &otp));
        assert!(!Otp::are_equal(&otp, "ABCDEFGH"));
        assert!(!Otp::are_equal(&otp, &otp[..7]));

        let mut longer_otp = String::from(&otp);
        longer_otp.push('A');
        assert!(!Otp::are_equal(&otp, &longer_otp));
    }
}
