use argonautica::config::Variant;
use argonautica::input::Salt;
use ring::rand::SecureRandom;

use crate::env;

pub fn hash_argon2id(password: &str) -> String {
    let mut hasher = argonautica::Hasher::default();
    hasher
        .configure_variant(Variant::Argon2id)
        .configure_hash_len(*env::hashing::HASH_LENGTH)
        .configure_iterations(*env::hashing::HASH_ITERATIONS)
        .configure_memory_size(*env::hashing::HASH_MEM_SIZE_KIB);

    let mut salt = vec![0u8; *env::hashing::SALT_LENGTH_BYTES];
    env::rand::SECURE_RANDOM_GENERATOR
        .fill(&mut salt)
        .expect("Failed to generate secure random numbers for hashing salt");

    hasher
        .with_secret_key(&*env::hashing::HASHING_SECRET_KEY)
        .with_salt(Salt::from(&salt))
        .with_password(password)
        .hash()
        .expect("Failed to hash password")
}

pub fn verify_hash(password: &str, hash: &str) -> bool {
    argonautica::Verifier::default()
        .with_hash(hash)
        .with_password(password)
        .with_secret_key(&*env::hashing::HASHING_SECRET_KEY)
        .verify()
        .expect("Failed to verify password hash")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hash_argon2id() {
        let password = "@Pa$$20rd-Test";
        let hash = hash_argon2id(&password);

        assert!(!hash.contains(&password));
    }

    #[test]
    fn test_verify_hash() {
        let password = "@Pa$$20rd-Test";
        let hash = hash_argon2id(password);

        assert!(verify_hash(password, &hash));
    }
}
