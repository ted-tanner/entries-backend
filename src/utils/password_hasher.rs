use log::error;
use ring::rand::SecureRandom;
use std::ffi::CStr;

use crate::env;
use crate::utils::argon2::{
    argon2_error_message, argon2id_ctx, Argon2_Context,
    Argon2_ErrorCodes_ARGON2_OK, Argon2_version_ARGON2_VERSION_13,
};

struct TokenizedHash {
    pub v: u32,
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
    pub b64_salt: String,
    pub b64_hash: String,
}

impl TokenizedHash {
    pub fn from_str(parameterized_hash: &str) -> Result<TokenizedHash, ()> {
        enum HashStates {
            Start,
            HashTypeStart,
            HashTypeA,
            HashTypeAr,
            HashTypeArg,
            HashTypeArgo,
            HashTypeArgon,
            HashTypeArgon2,
            HashTypeArgon2i,
            HashTypeArgon2id,
            HashTypeComplete,
            VKey,
            VEquals,
            VValue,
            VComplete,
            MKey,
            MEquals,
            MValue,
            MComplete,
            TKey,
            TEquals,
            TValue,
            TComplete,
            PKey,
            PEquals,
            PValue,
            PComplete,
            Salt,
            HashStart,
            Hash,
        }

        let mut state = HashStates::Start;

        let mut has_m = false;
        let mut has_t = false;
        let mut has_p = false;

        let mut v = String::with_capacity(10);
        let mut m = String::with_capacity(10);
        let mut t = String::with_capacity(10);
        let mut p = String::with_capacity(10);

        let mut salt = String::with_capacity(64);
        let mut hash = String::with_capacity(128);

        for c in parameterized_hash.chars() {
            match state {
                HashStates::Start => {
                    state = match c {
                        '$' => HashStates::HashTypeStart,
                        _ => return Err(()),
                    };
                }

                HashStates::HashTypeStart => {
                    state = match c {
                        'a' => HashStates::HashTypeA,
                        _ => return Err(()),
                    };
                }

                HashStates::HashTypeA => {
                    state = match c {
                        'r' => HashStates::HashTypeAr,
                        _ => return Err(()),
                    };
                }

                HashStates::HashTypeAr => {
                    state = match c {
                        'g' => HashStates::HashTypeArg,
                        _ => return Err(()),
                    };
                }

                HashStates::HashTypeArg => {
                    state = match c {
                        'o' => HashStates::HashTypeArgo,
                        _ => return Err(()),
                    };
                }

                HashStates::HashTypeArgo => {
                    state = match c {
                        'n' => HashStates::HashTypeArgon,
                        _ => return Err(()),
                    };
                }

                HashStates::HashTypeArgon => {
                    state = match c {
                        '2' => HashStates::HashTypeArgon2,
                        _ => return Err(()),
                    };
                }

                HashStates::HashTypeArgon2 => {
                    state = match c {
                        'i' => HashStates::HashTypeArgon2i,
                        _ => return Err(()),
                    };
                }

                HashStates::HashTypeArgon2i => {
                    state = match c {
                        'd' => HashStates::HashTypeArgon2id,
                        _ => return Err(()),
                    };
                }

                HashStates::HashTypeArgon2id => {
                    state = match c {
                        '$' => HashStates::HashTypeComplete,
                        _ => return Err(()),
                    };
                }

                HashStates::HashTypeComplete => {
                    state = match c {
                        'v' => HashStates::VKey,
                        _ => return Err(()),
                    };
                }

                HashStates::VKey => {
                    state = match c {
                        '=' => HashStates::VEquals,
                        _ => return Err(()),
                    };
                }

                HashStates::VEquals => {
                    if c.is_ascii_digit() {
                        v.push(c);
                        state = HashStates::VValue;
                    } else {
                        return Err(());
                    }
                }

                HashStates::VValue => {
                    if c == '$' {
                        state = HashStates::VComplete;
                    } else if c.is_ascii_digit() {
                        v.push(c);
                    } else {
                        return Err(());
                    }
                }

                HashStates::VComplete => {
                    state = match c {
                        'm' => HashStates::MKey,
                        't' => HashStates::TKey,
                        'p' => HashStates::PKey,
                        _ => return Err(()),
                    }
                }

                HashStates::MKey => {
                    if has_m {
                        return Err(());
                    }

                    state = match c {
                        '=' => HashStates::MEquals,
                        _ => return Err(()),
                    }
                }

                HashStates::MEquals => {
                    if c.is_ascii_digit() {
                        m.push(c);
                        state = HashStates::MValue;
                    } else {
                        return Err(());
                    }
                }

                HashStates::MValue => {
                    if c == ',' {
                        state = HashStates::MComplete;
                    } else if c.is_ascii_digit() {
                        m.push(c);
                    } else if c == '$' && has_t && has_p {
                        state = HashStates::Salt;
                    } else {
                        return Err(());
                    }
                }

                HashStates::MComplete => {
                    has_m = true;

                    state = match c {
                        't' => HashStates::TKey,
                        'p' => HashStates::PKey,
                        _ => return Err(()),
                    }
                }

                HashStates::TKey => {
                    if has_t {
                        return Err(());
                    }

                    state = match c {
                        '=' => HashStates::TEquals,
                        _ => return Err(()),
                    }
                }

                HashStates::TEquals => {
                    if c.is_ascii_digit() {
                        t.push(c);
                        state = HashStates::TValue;
                    } else {
                        return Err(());
                    }
                }

                HashStates::TValue => {
                    if c == ',' {
                        state = HashStates::TComplete;
                    } else if c.is_ascii_digit() {
                        t.push(c);
                    } else if c == '$' && has_m && has_p {
                        state = HashStates::Salt;
                    } else {
                        return Err(());
                    }
                }

                HashStates::TComplete => {
                    has_t = true;

                    state = match c {
                        'm' => HashStates::MKey,
                        'p' => HashStates::PKey,
                        _ => return Err(()),
                    }
                }

                HashStates::PKey => {
                    if has_p {
                        return Err(());
                    }

                    state = match c {
                        '=' => HashStates::PEquals,
                        _ => return Err(()),
                    }
                }

                HashStates::PEquals => {
                    if c.is_ascii_digit() {
                        p.push(c);
                        state = HashStates::PValue;
                    } else {
                        return Err(());
                    }
                }

                HashStates::PValue => {
                    if c == ',' {
                        state = HashStates::PComplete;
                    } else if c.is_ascii_digit() {
                        p.push(c);
                    } else if c == '$' && has_m && has_t {
                        state = HashStates::Salt;
                    } else {
                        return Err(());
                    }
                }

                HashStates::PComplete => {
                    has_p = true;

                    state = match c {
                        'm' => HashStates::MKey,
                        't' => HashStates::TKey,
                        _ => return Err(()),
                    }
                }

                HashStates::Salt => {
                    if c == '$' {
                        state = HashStates::HashStart;
                    } else {
                        salt.push(c);
                    }
                }

                HashStates::HashStart => {
                    if c == '$' {
                        return Err(());
                    }

                    hash.push(c);
                    state = HashStates::Hash;
                }

                HashStates::Hash => {
                    if c == '$' {
                        return Err(());
                    }

                    hash.push(c);
                }
            }
        }

        if std::mem::discriminant(&state) != std::mem::discriminant(&HashStates::Hash) {
            return Err(());
        }

        salt.shrink_to_fit();
        hash.shrink_to_fit();

        Ok(TokenizedHash {
            v: v.parse()
                .expect("Lexer put invalid character in v (should be an integer)"),
            memory_kib: m
                .parse()
                .expect("Lexer put invalid character in m (should be an integer)"),
            iterations: t
                .parse()
                .expect("Lexer put invalid character in t (should be an integer)"),
            lanes: p
                .parse()
                .expect("Lexer put invalid character in p (should be an integer)"),
            b64_salt: salt,
            b64_hash: hash,
        })
    }

    pub fn to_hash_string(self) -> String {
        format!(
            "$argon2id$v={}$m={},t={},p={}${}${}",
            self.v, self.memory_kib, self.iterations, self.lanes, self.b64_salt, self.b64_hash
        )
    }
}

pub fn hash_password(password: &str) -> String {
    let mut salt = vec![0u8; env::CONF.hashing.salt_length_bytes];

    env::rand::SECURE_RANDOM_GENERATOR
        .fill(&mut salt)
        .expect("Failed to generate secure random numbers for hashing salt");

    let mut hashing_key_mut = env::CONF.keys.hashing_key.clone();

    hash_argon2id(
        password,
        unsafe { hashing_key_mut.as_bytes_mut() },
        &mut salt[..],
        u32::try_from(env::CONF.hashing.hash_length).expect("Hash length is too big"),
        env::CONF.hashing.hash_iterations,
        env::CONF.hashing.hash_mem_size_kib,
        env::CONF.hashing.hash_lanes,
    )
}

pub fn verify_hash(password: &str, hash: &str) -> bool {
    let mut hashing_key_mut = env::CONF.keys.hashing_key.clone();
    verify_argon2id(password, hash, unsafe { hashing_key_mut.as_bytes_mut() })
}

pub fn hash_argon2id(
    password: &str,
    key: &mut [u8],
    salt: &mut [u8],
    hash_len: u32,
    iterations: u32,
    memory_kib: u32,
    lanes: u32,
) -> String {
    let mut password_mut = String::from(password);
    let mut hash_buffer = vec![0u8; usize::try_from(hash_len).expect("Invalid hash length")];

    let mut ctx = Argon2_Context {
        out: hash_buffer.as_mut_ptr(),
        outlen: u32::try_from(hash_buffer.len()).expect("Password hash is too long"),
        pwd: unsafe { password_mut.as_bytes_mut().as_mut_ptr() },
        pwdlen: u32::try_from(password_mut.len()).expect("Password is too long"),
        salt: salt.as_mut_ptr(),
        saltlen: u32::try_from(salt.len()).expect("Password salt is too long"),
        secret: key.as_mut_ptr(),
        secretlen: u32::try_from(key.len()).expect("Key is too long"),
        ad: std::ptr::null_mut(),
        adlen: 0,
        t_cost: iterations,
        m_cost: memory_kib,
        lanes: lanes,
        threads: lanes,
        version: Argon2_version_ARGON2_VERSION_13,
        allocate_cbk: None,
        free_cbk: None,
        flags: 0,
    };

    let result = unsafe { argon2id_ctx(&mut ctx as *mut Argon2_Context) };

    if result != Argon2_ErrorCodes_ARGON2_OK {
        panic!("Failed to hash password: {}", unsafe {
            CStr::from_ptr(argon2_error_message(result))
                .to_string_lossy()
        });
    }

    let hash = TokenizedHash {
        v: 19,
        memory_kib: memory_kib,
        iterations: iterations,
        lanes: lanes,
        b64_salt: base64::encode_config(salt, base64::STANDARD_NO_PAD),
        b64_hash: base64::encode_config(hash_buffer, base64::STANDARD_NO_PAD),
    };

    hash.to_hash_string()
}

pub fn verify_argon2id(password: &str, hash: &str, key: &mut [u8]) -> bool {
    let tokenized_hash = match TokenizedHash::from_str(hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Hash passed to verifier was invalid");
            return false;
        }
    };

    let mut decoded_salt = base64::decode_config(tokenized_hash.b64_salt, base64::STANDARD_NO_PAD)
        .expect("Failed to decode salt");
    let decoded_hash = base64::decode_config(tokenized_hash.b64_hash, base64::STANDARD_NO_PAD)
        .expect("Failed to decode hash");

    let hashed_password = hash_argon2id(
        password,
        key,
        &mut decoded_salt[..],
        decoded_hash.len().try_into().expect("Hash is too long"),
        tokenized_hash.iterations,
        tokenized_hash.memory_kib,
        tokenized_hash.lanes,
    );

    let tokenized_verification_hash = match TokenizedHash::from_str(&hashed_password) {
        Ok(h) => h,
        Err(_) => {
            error!("Hash passed to verifier was invalid");
            return false;
        }
    };

    let decoded_verification_hash =
        base64::decode_config(tokenized_verification_hash.b64_hash, base64::STANDARD_NO_PAD)
        .expect("Failed to decode hash");

    let mut is_valid = 0u8;

    // Do bitwise comparison to prevent timing attacks (entire length of string must be compared
    for i in 0..decoded_hash.len() {
        is_valid |= decoded_hash[i] ^ decoded_verification_hash[i];
    }

    return is_valid == 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Test TokenizedHash impl

    #[actix_rt::test]
    async fn test_hash_password() {
        let password = "@Pa$$20rd-Test";
        let hash = hash_password(password);

        assert!(!hash.contains(&password));
    }

    #[actix_rt::test]
    async fn test_verify_hash() {
        let password = "@Pa$$20rd-Test";
        let hash = hash_password(password);

        // TODO: Hard code hash

        assert!(verify_hash(password, &hash));
    }
}
