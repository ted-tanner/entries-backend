use log::error;
use ring::rand::{SecureRandom, SystemRandom};
use std::ffi::CStr;

use crate::argon2::{
    argon2_error_message, argon2id_ctx, Argon2_Context, Argon2_ErrorCodes_ARGON2_OK,
    Argon2_version_ARGON2_VERSION_13,
};

lazy_static! {
    pub static ref SECURE_RANDOM_GENERATOR: SystemRandom = SystemRandom::new();
}

struct TokenizedHash {
    pub v: u32,
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
    pub b64_salt: String,
    pub b64_hash: String,
}

#[derive(Clone, Debug)]
pub struct HashParams {
    pub salt_len: usize,
    pub hash_len: u32,
    pub hash_iterations: u32,
    // hash_mem_size_kib must be a power of 2 and at least 128
    pub hash_mem_size_kib: u32,
    pub hash_lanes: u32,
}

pub struct BinaryHash {
    pub v: u32,
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
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
}

impl BinaryHash {
    #[inline]
    pub fn into_hash_string(self) -> String {
        let b64_salt = base64::encode_config(self.salt, base64::STANDARD_NO_PAD);
        let b64_hash = base64::encode_config(self.hash, base64::STANDARD_NO_PAD);
        format!(
            "$argon2id$v={}$m={},t={},p={}${}${}",
            self.v, self.memory_kib, self.iterations, self.lanes, b64_salt, b64_hash
        )
    }
}

#[inline]
pub fn hash_password(password: &str, hash_params: &HashParams, hashing_key: &[u8]) -> String {
    let mut salt = vec![0u8; hash_params.salt_len];

    SECURE_RANDOM_GENERATOR
        .fill(&mut salt)
        .expect("Failed to generate secure random numbers for hashing salt");

    hash_argon2id(
        password,
        hashing_key,
        &salt[..],
        hash_params.hash_len,
        hash_params.hash_iterations,
        hash_params.hash_mem_size_kib,
        hash_params.hash_lanes,
    )
    .into_hash_string()
}

#[inline]
pub fn verify_hash(password: &str, hash: &str, hashing_key: &[u8]) -> bool {
    verify_argon2id(password, hash, hashing_key)
}

pub fn hash_argon2id(
    password: &str,
    key: &[u8],
    salt: &[u8],
    hash_len: u32,
    iterations: u32,
    memory_kib: u32,
    lanes: u32,
) -> BinaryHash {
    let mut hash_buffer = vec![0u8; usize::try_from(hash_len).expect("Invalid hash length")];

    let mut ctx = Argon2_Context {
        out: hash_buffer.as_mut_ptr(),
        outlen: u32::try_from(hash_buffer.len()).expect("Password hash is too long"),
        pwd: password.as_bytes() as *const _ as *mut _,
        pwdlen: u32::try_from(password.len()).expect("Password is too long"),
        salt: salt.as_ptr() as *mut _,
        saltlen: u32::try_from(salt.len()).expect("Password salt is too long"),
        secret: key.as_ptr() as *mut _,
        secretlen: u32::try_from(key.len()).expect("Key is too long"),
        ad: std::ptr::null_mut(),
        adlen: 0,
        t_cost: iterations,
        m_cost: memory_kib,
        lanes,
        threads: lanes,
        version: Argon2_version_ARGON2_VERSION_13,
        allocate_cbk: None,
        free_cbk: None,
        flags: 0,
    };

    let result = unsafe { argon2id_ctx(&mut ctx as *mut Argon2_Context) };

    if result != Argon2_ErrorCodes_ARGON2_OK {
        let err_msg = format!("Failed to hash password: {}", unsafe {
            std::str::from_utf8_unchecked(CStr::from_ptr(argon2_error_message(result)).to_bytes())
        });
        error!("{}", err_msg);
        panic!("{}", err_msg);
    }

    BinaryHash {
        v: 19,
        memory_kib,
        iterations,
        lanes,
        salt: Vec::from(salt),
        hash: hash_buffer,
    }
}

pub fn verify_argon2id(password: &str, hash: &str, key: &[u8]) -> bool {
    let tokenized_hash = match TokenizedHash::from_str(hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Hash passed to verifier was invalid");
            return false;
        }
    };

    let decoded_salt = base64::decode_config(tokenized_hash.b64_salt, base64::STANDARD_NO_PAD)
        .expect("Failed to decode salt");
    let decoded_hash = base64::decode_config(tokenized_hash.b64_hash, base64::STANDARD_NO_PAD)
        .expect("Failed to decode hash");

    let hashed_password = hash_argon2id(
        password,
        key,
        &decoded_salt[..],
        decoded_hash.len().try_into().expect("Hash is too long"),
        tokenized_hash.iterations,
        tokenized_hash.memory_kib,
        tokenized_hash.lanes,
    );

    if hashed_password.v != tokenized_hash.v {
        return false;
    }

    let mut is_valid = 0u8;

    if decoded_hash.len() != hashed_password.hash.len() || decoded_hash.is_empty() {
        return false;
    }

    // Do bitwise comparison to prevent timing attacks (entire length of string must be
    // compared)
    for (i, decoded_hash_byte) in decoded_hash.iter().enumerate() {
        is_valid |= decoded_hash_byte ^ hashed_password.hash[i];
    }

    is_valid == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_hash_into_hash_string() {
        let hash = BinaryHash {
            v: 19,
            memory_kib: 128,
            iterations: 3,
            lanes: 2,
            salt: vec![1, 2, 3, 4, 5, 6, 7, 8],
            hash: base64::decode_config(
                "ypJ3pKxN4aWGkwMv0TOb08OIzwrfK1SZWy64vyTLKo8",
                base64::STANDARD_NO_PAD,
            )
            .unwrap()
            .to_vec(),
        };

        assert_eq!(hash.into_hash_string(),
                   String::from(
                       "$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg$ypJ3pKxN4aWGkwMv0TOb08OIzwrfK1SZWy64vyTLKo8"
                   ));
    }

    #[test]
    fn test_tokenized_hash_from_str() {
        let tokenized_hash = TokenizedHash::from_str(
            "$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        )
        .unwrap();

        assert_eq!(tokenized_hash.v, 19);
        assert_eq!(tokenized_hash.memory_kib, 128);
        assert_eq!(tokenized_hash.iterations, 3);
        assert_eq!(tokenized_hash.lanes, 2);
        assert_eq!(tokenized_hash.b64_salt, String::from("AQIDBAUGBwg"));
        assert_eq!(
            tokenized_hash.b64_hash,
            String::from("7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc")
        );

        let tokenized_hash = TokenizedHash::from_str(
            "$argon2id$v=19$t=3,m=128,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        )
        .unwrap();

        assert_eq!(tokenized_hash.v, 19);
        assert_eq!(tokenized_hash.memory_kib, 128);
        assert_eq!(tokenized_hash.iterations, 3);
        assert_eq!(tokenized_hash.lanes, 2);
        assert_eq!(tokenized_hash.b64_salt, String::from("AQIDBAUGBwg"));
        assert_eq!(
            tokenized_hash.b64_hash,
            String::from("7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc")
        );

        let tokenized_hash = TokenizedHash::from_str(
            "$argon2id$v=19$p=2,m=128,t=3$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        )
        .unwrap();

        assert_eq!(tokenized_hash.v, 19);
        assert_eq!(tokenized_hash.memory_kib, 128);
        assert_eq!(tokenized_hash.iterations, 3);
        assert_eq!(tokenized_hash.lanes, 2);
        assert_eq!(tokenized_hash.b64_salt, String::from("AQIDBAUGBwg"));
        assert_eq!(
            tokenized_hash.b64_hash,
            String::from("7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc")
        );

        let tokenized_hash = TokenizedHash::from_str(
            "$argon2id$v=19$t=3,p=2,m=128$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        )
        .unwrap();

        assert_eq!(tokenized_hash.v, 19);
        assert_eq!(tokenized_hash.memory_kib, 128);
        assert_eq!(tokenized_hash.iterations, 3);
        assert_eq!(tokenized_hash.lanes, 2);
        assert_eq!(tokenized_hash.b64_salt, String::from("AQIDBAUGBwg"));
        assert_eq!(
            tokenized_hash.b64_hash,
            String::from("7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc")
        );
    }

    #[test]
    fn test_invalid_tokenized_hash_from_str() {
        let tokenized_hash = TokenizedHash::from_str(
            "$argon2id$v=19$m=128,t=3,p=2,$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(tokenized_hash.is_err());

        let tokenized_hash = TokenizedHash::from_str(
            "$argon2id$v=19$t=3,m=128,p=2,m=128$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc"
        );

        assert!(tokenized_hash.is_err());

        let tokenized_hash = TokenizedHash::from_str(
            "$argon2i$v=19$p=2m=128,t=3$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(tokenized_hash.is_err());

        let tokenized_hash = TokenizedHash::from_str(
            "$argon2id$t=3,p=2,m=128$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(tokenized_hash.is_err());

        let tokenized_hash = TokenizedHash::from_str(
            "$argon2i$v=19$m=128,t=3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(tokenized_hash.is_err());

        let tokenized_hash = TokenizedHash::from_str(
            "$argon2id$v=19$m=128,t=3,p=2AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(tokenized_hash.is_err());

        let tokenized_hash = TokenizedHash::from_str(
            "argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(tokenized_hash.is_err());

        let tokenized_hash = TokenizedHash::from_str(
            "$argon2id$v=19$m=128,t3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(tokenized_hash.is_err());

        let tokenized_hash = TokenizedHash::from_str(
            "$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(tokenized_hash.is_err());

        let tokenized_hash = TokenizedHash::from_str(
            "$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc$",
        );

        assert!(tokenized_hash.is_err());

        let tokenized_hash = TokenizedHash::from_str("$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg$$");

        assert!(tokenized_hash.is_err());

        let tokenized_hash = TokenizedHash::from_str(
            "$argon2id$v=19$m=128,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(tokenized_hash.is_err());

        let tokenized_hash = TokenizedHash::from_str(
            "$argon2id$v=19$t=2,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(tokenized_hash.is_err());

        let tokenized_hash = TokenizedHash::from_str(
            "$argon2id$v=19$t=2,m=128$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(tokenized_hash.is_err());
    }

    #[test]
    fn test_hash_password() {
        let password = "@Pa$$20rd-Test";

        let hash_params = HashParams {
            salt_len: 16,
            hash_len: 32,
            hash_iterations: 2,
            hash_mem_size_kib: 128,
            hash_lanes: 2,
        };

        let hash = hash_password(
            password,
            &hash_params,
            vec![30, 23, 4, 2, 3, 56, 56].as_slice(),
        );

        assert!(!hash.contains(password));
    }

    #[test]
    fn test_verify_hash() {
        let password = "@Pa$$20rd-Test";

        let hash_params = HashParams {
            salt_len: 16,
            hash_len: 32,
            hash_iterations: 2,
            hash_mem_size_kib: 128,
            hash_lanes: 2,
        };

        let hash = hash_password(
            password,
            &hash_params,
            vec![30, 23, 4, 2, 3, 56, 56].as_slice(),
        );

        assert!(verify_hash(
            password,
            &hash,
            vec![30, 23, 4, 2, 3, 56, 56].as_slice()
        ));
    }

    #[test]
    fn test_verify_incorrect_password() {
        let password = "@Pa$$20rd-Test";

        let hash_params = HashParams {
            salt_len: 16,
            hash_len: 32,
            hash_iterations: 2,
            hash_mem_size_kib: 128,
            hash_lanes: 2,
        };

        let hash = hash_password(
            password,
            &hash_params,
            vec![30, 23, 4, 2, 3, 56, 56].as_slice(),
        );

        assert!(!verify_hash(
            "@pa$$20rd-Test",
            &hash,
            vec![30, 23, 4, 2, 3, 56, 56].as_slice()
        ));
    }

    #[test]
    fn test_verify_incorrect_key() {
        let password = "@Pa$$20rd-Test";

        let hash_params = HashParams {
            salt_len: 16,
            hash_len: 32,
            hash_iterations: 2,
            hash_mem_size_kib: 128,
            hash_lanes: 2,
        };

        let hash = hash_password(
            password,
            &hash_params,
            vec![30, 23, 4, 2, 3, 56, 56].as_slice(),
        );

        assert!(!verify_hash(
            password,
            &hash,
            vec![30, 23, 4, 2, 4, 56, 56].as_slice()
        ));
    }
}
