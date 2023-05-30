use rand::distributions::Alphanumeric;
use rand::rngs::OsRng;
use rand::Rng;

pub struct Otp {}

impl Otp {
    pub fn generate(length: usize) -> String {
        OsRng
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(|c| char::from(c).to_ascii_uppercase())
            .collect()
    }

    pub fn generate_multiple(length: usize, count: usize) -> Vec<String> {
        let mut backup_codes = Vec::with_capacity(count);
        for _ in 0..count {
            backup_codes.push(Self::generate(length));
        }

        backup_codes
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
