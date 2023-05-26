use rand::distributions::Alphanumeric;
use rand::rngs::OsRng;
use rand::Rng;

pub struct Otp {}

impl Otp {
    pub fn generate() -> String {
        OsRng
            .sample_iter(&Alphanumeric)
            .take(8)
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
