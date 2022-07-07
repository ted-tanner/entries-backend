use ring::rand::SecureRandom;

use crate::env;
use crate::utils::argon2::{
    argon2id_ctx, argon2id_verify_ctx, Argon2_Context, Argon2_ErrorCodes_ARGON2_OK,
    Argon2_ErrorCodes_ARGON2_VERIFY_MISMATCH, Argon2_version_ARGON2_VERSION_13,
};

pub fn hash_argon2id(password: &str) -> String {
    let mut password_mut = String::from(password);
    let mut hashing_key_mut = env::CONF.keys.hashing_key.clone();

    let mut salt = vec![0u8; env::CONF.hashing.salt_length_bytes];
    env::rand::SECURE_RANDOM_GENERATOR
        .fill(&mut salt)
        .expect("Failed to generate secure random numbers for hashing salt");

    let mut password_buffer = vec![0u8; env::CONF.hashing.hash_length];

    let mut ctx = Argon2_Context {
        out: password_buffer.as_mut_ptr(),
        outlen: u32::try_from(password_buffer.len()).expect("Password hash is too long"),
        pwd: unsafe { password_mut.as_bytes_mut().as_mut_ptr() },
        pwdlen: u32::try_from(password_mut.len()).expect("Password is too long"),
        salt: salt.as_mut_ptr(),
        saltlen: u32::try_from(salt.len()).expect("Password salt is too long"),
        secret: unsafe { hashing_key_mut.as_bytes_mut().as_mut_ptr() },
        secretlen: u32::try_from(hashing_key_mut.len()).expect("Key is too long"),
        ad: std::ptr::null_mut(),
        adlen: 0,
        t_cost: env::CONF.hashing.hash_lanes,
        m_cost: env::CONF.hashing.hash_mem_size_kib,
        lanes: env::CONF.hashing.hash_lanes,
        threads: env::CONF.hashing.hash_lanes,
        version: Argon2_version_ARGON2_VERSION_13,
        allocate_cbk: None,
        free_cbk: None,
        flags: 0,
    };

    let result = unsafe { argon2id_ctx(&mut ctx as *mut Argon2_Context) };

    if result != Argon2_ErrorCodes_ARGON2_OK {
        panic!("Failed to hash password");
    }

    base64::encode_config(password_buffer, base64::URL_SAFE_NO_PAD)
}

pub fn verify_hash(password: &str, hash: &str) -> bool {
    let mut password_mut = String::from(password);
    let mut hashing_key_mut = env::CONF.keys.hashing_key.clone();

    let mut salt = vec![0u8; env::CONF.hashing.salt_length_bytes];
    let mut password_buffer = vec![0u8; env::CONF.hashing.hash_length];

    let mut ctx = Argon2_Context {
        out: password_buffer.as_mut_ptr(),
        outlen: u32::try_from(password_buffer.len()).expect("Password hash is too long"),
        pwd: unsafe { password_mut.as_bytes_mut().as_mut_ptr() },
        pwdlen: u32::try_from(password_mut.len()).expect("Password is too long"),
        salt: salt.as_mut_ptr(),
        saltlen: u32::try_from(salt.len()).expect("Password salt is too long"),
        secret: unsafe { hashing_key_mut.as_bytes_mut().as_mut_ptr() },
        secretlen: u32::try_from(hashing_key_mut.len()).expect("Key is too long"),
        ad: std::ptr::null_mut(),
        adlen: 0,
        t_cost: env::CONF.hashing.hash_lanes,
        m_cost: env::CONF.hashing.hash_mem_size_kib,
        lanes: env::CONF.hashing.hash_lanes,
        threads: env::CONF.hashing.hash_lanes,
        version: Argon2_version_ARGON2_VERSION_13,
        allocate_cbk: None,
        free_cbk: None,
        flags: 0,
    };

    let mut decoded_hash = base64::decode_config(hash.as_bytes(), base64::URL_SAFE_NO_PAD)
        .expect("Failed to decode hash");
    let decoded_hash_i8 = unsafe {
        std::slice::from_raw_parts(
            decoded_hash.as_mut_ptr() as *mut i8,
            decoded_hash.len(),
        )
    };

    let result =
        unsafe { argon2id_verify_ctx(&mut ctx as *mut Argon2_Context, decoded_hash_i8.as_ptr()) };

    if result != Argon2_ErrorCodes_ARGON2_OK && result != Argon2_ErrorCodes_ARGON2_VERIFY_MISMATCH {
        panic!("Failed to hash password");
    }

    result == Argon2_ErrorCodes_ARGON2_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_rt::test]
    async fn test_hash_argon2id() {
        let password = "@Pa$$20rd-Test";
        let hash = hash_argon2id(password);

        assert!(!hash.contains(&password));
    }

    #[actix_rt::test]
    async fn test_verify_hash() {
        let password = "@Pa$$20rd-Test";
        let hash = hash_argon2id(password);

        assert!(verify_hash(password, &hash));
    }
}
