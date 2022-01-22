use argonautica::config::Variant;
use argonautica::input::Salt;
use ring::rand::SecureRandom;

use crate::env;

pub fn hash_argon2id(password: &str) -> String {
    let mut hasher = argonautica::Hasher::default();
    hasher
        .configure_variant(Variant::Argon2id)
        .configure_lanes(env::CONF.hashing.hash_lanes)
        .configure_threads(env::CONF.hashing.hash_lanes)
        .configure_hash_len(env::CONF.hashing.hash_length)
        .configure_iterations(env::CONF.hashing.hash_iterations)
        .configure_memory_size(env::CONF.hashing.hash_mem_size_kib);

    let mut salt = vec![0u8; env::CONF.hashing.salt_length_bytes];
    env::rand::SECURE_RANDOM_GENERATOR
        .fill(&mut salt)
        .expect("Failed to generate secure random numbers for hashing salt");

    hasher
        .with_secret_key(&env::CONF.keys.hashing_key)
        .with_salt(Salt::from(&salt))
        .with_password(password)
        .hash()
        .expect("Failed to hash password")
}

pub fn verify_hash(password: &str, hash: &str) -> bool {
    argonautica::Verifier::default()
        .with_hash(hash)
        .with_password(password)
        .with_secret_key(&env::CONF.keys.hashing_key)
        .verify()
        .expect("Failed to verify password hash")
}

#[cfg(test)]
mod tests {
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
