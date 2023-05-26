use rand::{rngs::OsRng, Fill};
use std::ffi::CStr;
use std::fmt;
use std::mem::MaybeUninit;
use std::{default::Default, str::FromStr};

use crate::argon2_bindings::{
    argon2_error_message, argon2id_ctx, Argon2_Context, Argon2_ErrorCodes_ARGON2_OK,
    Argon2_version_ARGON2_VERSION_13,
};

#[derive(Debug)]
pub enum Argon2idError {
    InvalidParameter(&'static str),
    InvalidHash(&'static str),
    CLibError(String),
}

impl std::error::Error for Argon2idError {}

impl fmt::Display for Argon2idError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Argon2idError::InvalidParameter(msg) => {
                write!(f, "Argon2idError: Invalid parameter: {}", msg)
            }
            Argon2idError::InvalidHash(msg) => write!(f, "Argon2idError: Invalid hash: {}", msg),
            Argon2idError::CLibError(msg) => {
                write!(f, "Argon2idError: Error from C library: {}", msg)
            }
        }
    }
}

pub struct Secret<'a>(&'a [u8]);

impl<'a> Secret<'a> {
    pub fn using_bytes(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
}

pub struct Hasher<'a> {
    custom_salt: Option<&'a [u8]>,
    salt_len: u32,
    hash_len: u32,
    iterations: u32,
    mem_cost_kib: u32,
    threads: u32,
    secret: Option<Secret<'a>>,
}

impl<'a> Default for Hasher<'a> {
    fn default() -> Self {
        Self {
            custom_salt: None,
            salt_len: 16,
            hash_len: 32,
            iterations: 20,
            mem_cost_kib: 62500,
            threads: 1,
            secret: None,
        }
    }
}

impl<'a> Hasher<'a> {
    /// When left unspecified, a salt is generated using a cryptographically-secure random
    /// number generator. In most cases, a salt shouldn't be specified using this method. Only
    /// use this function if you are trying to generate a hash deterministically with a known
    /// salt and a randomly generated salt will not suffice.
    pub fn custom_salt(mut self, salt: &'a [u8]) -> Self {
        self.custom_salt = Some(salt);
        self
    }

    /// The length of the salt for the hash. Specifying a salt that is too short can decrease
    /// the security of the generated hash.
    ///
    /// If a salt is specified manually using `Self::salt()` (an rare case), the length of
    /// the provided salt will overwrite the length specified here.
    pub fn salt_length(mut self, salt_len: u32) -> Self {
        self.salt_len = salt_len;
        self
    }

    pub fn hash_length(mut self, hash_len: u32) -> Self {
        self.hash_len = hash_len;
        self
    }

    pub fn iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    pub fn memory_cost_kib(mut self, cost: u32) -> Self {
        self.mem_cost_kib = cost;
        self
    }

    pub fn threads(mut self, threads: u32) -> Self {
        self.threads = threads;
        self
    }

    pub fn secret(mut self, secret: Secret<'a>) -> Self {
        self.secret = Some(secret);
        self
    }

    pub fn hash(self, password: &str) -> Result<Hash, Argon2idError> {
        let hash_len_usize = match usize::try_from(self.hash_len) {
            Ok(l) => l,
            Err(_) => return Err(Argon2idError::InvalidParameter("Hash length is too big")),
        };

        let mut hash_buffer = MaybeUninit::new(Vec::with_capacity(hash_len_usize));
        let mut hash_buffer = unsafe {
            (*hash_buffer.as_mut_ptr()).set_len(hash_len_usize);
            (*hash_buffer.as_mut_ptr())
                .try_fill(&mut OsRng)
                .expect("Failed to fill buffer with random bytes");

            hash_buffer.assume_init()
        };

        let (salt_len_u32, salt_len_usize) = if let Some(s) = self.custom_salt {
            let salt_len_u32 = match u32::try_from(s.len()) {
                Ok(l) => l,
                Err(_) => return Err(Argon2idError::InvalidParameter("Salt length is too big")),
            };

            (salt_len_u32, s.len())
        } else {
            let salt_len_usize = match usize::try_from(self.salt_len) {
                Ok(l) => l,
                Err(_) => return Err(Argon2idError::InvalidParameter("Salt length is too big")),
            };

            (self.salt_len, salt_len_usize)
        };

        let salt;
        let salt = if let Some(s) = self.custom_salt {
            s
        } else {
            let mut rand_salt = MaybeUninit::new(Vec::with_capacity(salt_len_usize));
            salt = unsafe {
                (*rand_salt.as_mut_ptr()).set_len(salt_len_usize);
                (*rand_salt.as_mut_ptr())
                    .try_fill(&mut OsRng)
                    .expect("Failed to fill buffer with random bytes");

                rand_salt.assume_init()
            };

            &salt
        };

        let (secret_ptr, secret_len) = {
            if let Some(s) = self.secret {
                let length = match s.0.len().try_into() {
                    Ok(l) => l,
                    Err(_) => return Err(Argon2idError::InvalidParameter("Secret is too long")),
                };

                (s.0.as_ptr() as *mut _, length)
            } else {
                (std::ptr::null_mut(), 0)
            }
        };

        // Some buffers here are cast to *mut to pass to C. C will not modify these buffers
        // so this is safe
        let mut ctx = Argon2_Context {
            out: hash_buffer.as_mut_ptr(),
            // hash_len was originally converted from a u32 to a usize, so this is safe
            outlen: self.hash_len,
            pwd: password.as_bytes() as *const _ as *mut _,
            pwdlen: match password.len().try_into() {
                Ok(l) => l,
                Err(_) => return Err(Argon2idError::InvalidParameter("Password is too long")),
            },
            salt: salt.as_ptr() as *mut _,
            // Careful not to use self.salt_len here; it may be overridden if a custom salt
            // has been specified
            saltlen: salt_len_u32,
            secret: secret_ptr,
            secretlen: secret_len,
            ad: std::ptr::null_mut(),
            adlen: 0,
            t_cost: self.iterations,
            m_cost: self.mem_cost_kib,
            lanes: self.threads,
            threads: self.threads,
            version: Argon2_version_ARGON2_VERSION_13,
            allocate_cbk: None,
            free_cbk: None,
            flags: 0,
        };

        let result = unsafe { argon2id_ctx(&mut ctx as *mut _) };

        if result != Argon2_ErrorCodes_ARGON2_OK {
            let err_msg = String::from_utf8_lossy(unsafe {
                CStr::from_ptr(argon2_error_message(result)).to_bytes()
            });

            return Err(Argon2idError::CLibError(err_msg.into_owned()));
        }

        Ok(Hash {
            mem_cost_kib: self.mem_cost_kib,
            iterations: self.iterations,
            threads: self.threads,
            salt: Vec::from(salt),
            hash: hash_buffer,
        })
    }
}

pub struct Hash {
    mem_cost_kib: u32,
    iterations: u32,
    threads: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

impl ToString for Hash {
    fn to_string(&self) -> String {
        let b64_salt = base64::encode_config(&self.salt, base64::STANDARD_NO_PAD);
        let b64_hash = base64::encode_config(&self.hash, base64::STANDARD_NO_PAD);

        format!(
            "$argon2id$v={}$m={},t={},p={}${}${}",
            Argon2_version_ARGON2_VERSION_13,
            self.mem_cost_kib,
            self.iterations,
            self.threads,
            b64_salt,
            b64_hash,
        )
    }
}

impl FromStr for Hash {
    type Err = Argon2idError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tokenized_hash = TokenizedHash::from_str(s)?;

        if tokenized_hash.v != Argon2_version_ARGON2_VERSION_13 {
            return Err(Argon2idError::InvalidHash("Hash version is unsupported"));
        }

        let decoded_salt =
            match base64::decode_config(tokenized_hash.b64_salt, base64::STANDARD_NO_PAD) {
                Ok(s) => s,
                Err(_) => {
                    return Err(Argon2idError::InvalidHash(
                        "Invalid character in base64-encoded salt",
                    ))
                }
            };

        let decoded_hash =
            match base64::decode_config(tokenized_hash.b64_hash, base64::STANDARD_NO_PAD) {
                Ok(h) => h,
                Err(_) => {
                    return Err(Argon2idError::InvalidHash(
                        "Invalid character in base64-encoded hash",
                    ))
                }
            };

        Ok(Self {
            mem_cost_kib: tokenized_hash.mem_cost_kib,
            iterations: tokenized_hash.iterations,
            threads: tokenized_hash.threads,
            salt: decoded_salt,
            hash: decoded_hash,
        })
    }
}

impl Hash {
    pub fn as_bytes<'a>(&'a self) -> &'a [u8] {
        &self.hash
    }

    pub fn salt<'a>(&'a self) -> &'a [u8] {
        &self.salt
    }

    #[inline]
    pub fn verify(&self, password: &str) -> bool {
        self.verify_with_or_without_secret(password, None)
    }

    #[inline]
    pub fn verify_with_secret(&self, password: &str, secret: Secret) -> bool {
        self.verify_with_or_without_secret(password, Some(secret))
    }

    fn verify_with_or_without_secret(&self, password: &str, secret: Option<Secret>) -> bool {
        let hash_length: u32 = match self.hash.len().try_into() {
            Ok(l) => l,
            Err(_) => return false,
        };

        let mut hash_builder = Hasher::default()
            .custom_salt(&self.salt)
            .hash_length(hash_length)
            .iterations(self.iterations)
            .memory_cost_kib(self.mem_cost_kib)
            .threads(self.threads);

        if let Some(s) = secret {
            hash_builder = hash_builder.secret(s);
        }

        let hashed_password = match hash_builder.hash(password) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let mut hashes_dont_match = 0u8;

        if self.hash.len() != hashed_password.hash.len() || self.hash.is_empty() {
            return false;
        }

        // Do bitwise comparison to prevent timing attacks (entire length of string must be
        // compared)
        for (i, hash_byte) in hashed_password.hash.iter().enumerate() {
            unsafe {
                hashes_dont_match |= hash_byte ^ self.hash.get_unchecked(i);
            }
        }

        hashes_dont_match == 0
    }
}

struct TokenizedHash {
    v: u32,
    mem_cost_kib: u32,
    iterations: u32,
    threads: u32,
    b64_salt: String,
    b64_hash: String,
}

impl TokenizedHash {
    fn from_str(parameterized_hash: &str) -> Result<TokenizedHash, Argon2idError> {
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

        let mut v = 0..0;
        let mut m = 0..0;
        let mut t = 0..0;
        let mut p = 0..0;

        let mut salt = String::with_capacity(22); // 16 bytes, base64-encoded (no padding)
        let mut hash = String::new();

        for (i, c) in parameterized_hash.chars().enumerate() {
            match state {
                HashStates::Start => {
                    state = match c {
                        '$' => HashStates::HashTypeStart,
                        _ => return Err(Argon2idError::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeStart => {
                    state = match c {
                        'a' => HashStates::HashTypeA,
                        _ => return Err(Argon2idError::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeA => {
                    state = match c {
                        'r' => HashStates::HashTypeAr,
                        _ => return Err(Argon2idError::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeAr => {
                    state = match c {
                        'g' => HashStates::HashTypeArg,
                        _ => return Err(Argon2idError::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArg => {
                    state = match c {
                        'o' => HashStates::HashTypeArgo,
                        _ => return Err(Argon2idError::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArgo => {
                    state = match c {
                        'n' => HashStates::HashTypeArgon,
                        _ => return Err(Argon2idError::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArgon => {
                    state = match c {
                        '2' => HashStates::HashTypeArgon2,
                        _ => return Err(Argon2idError::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArgon2 => {
                    state = match c {
                        'i' => HashStates::HashTypeArgon2i,
                        _ => return Err(Argon2idError::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArgon2i => {
                    state = match c {
                        'd' => HashStates::HashTypeArgon2id,
                        _ => return Err(Argon2idError::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArgon2id => {
                    state = match c {
                        '$' => HashStates::HashTypeComplete,
                        _ => return Err(Argon2idError::InvalidHash("Missing '$' delimiter")),
                    };
                }

                HashStates::HashTypeComplete => {
                    state = match c {
                        'v' => HashStates::VKey,
                        _ => return Err(Argon2idError::InvalidHash("Missing algorithm version")),
                    };
                }

                HashStates::VKey => {
                    state = match c {
                        '=' => HashStates::VEquals,
                        _ => return Err(Argon2idError::InvalidHash("Missing algorithm version")),
                    };
                }

                HashStates::VEquals => {
                    v = i..(i + 1);
                    state = HashStates::VValue;
                }

                HashStates::VValue => {
                    if c == '$' {
                        state = HashStates::VComplete;
                    } else {
                        v.end += 1;
                    }
                }

                HashStates::VComplete => {
                    state = match c {
                        'm' => HashStates::MKey,
                        't' => HashStates::TKey,
                        'p' => HashStates::PKey,
                        _ => {
                            return Err(Argon2idError::InvalidHash(
                                "Unrecognized or missing parameter",
                            ))
                        }
                    }
                }

                HashStates::MKey => {
                    if has_m {
                        return Err(Argon2idError::InvalidHash("Duplicate key 'm'"));
                    }

                    state = match c {
                        '=' => HashStates::MEquals,
                        _ => return Err(Argon2idError::InvalidHash("Missing 'm' parameter")),
                    }
                }

                HashStates::MEquals => {
                    m = i..(i + 1);
                    state = HashStates::MValue;
                }

                HashStates::MValue => {
                    if c == ',' {
                        state = HashStates::MComplete;
                    } else if c == '$' && has_t && has_p {
                        state = HashStates::Salt;
                    } else {
                        m.end += 1;
                    }
                }

                HashStates::MComplete => {
                    has_m = true;

                    state = match c {
                        't' => HashStates::TKey,
                        'p' => HashStates::PKey,
                        _ => {
                            return Err(Argon2idError::InvalidHash(
                                "Unrecognized or missing parameter",
                            ))
                        }
                    }
                }

                HashStates::TKey => {
                    if has_t {
                        return Err(Argon2idError::InvalidHash("Duplicate key 't'"));
                    }

                    state = match c {
                        '=' => HashStates::TEquals,
                        _ => return Err(Argon2idError::InvalidHash("Missing 't' paramter")),
                    }
                }

                HashStates::TEquals => {
                    t = i..(i + 1);
                    state = HashStates::TValue;
                }

                HashStates::TValue => {
                    if c == ',' {
                        state = HashStates::TComplete;
                    } else if c == '$' && has_m && has_p {
                        state = HashStates::Salt;
                    } else {
                        t.end += 1;
                    }
                }

                HashStates::TComplete => {
                    has_t = true;

                    state = match c {
                        'm' => HashStates::MKey,
                        'p' => HashStates::PKey,
                        _ => {
                            return Err(Argon2idError::InvalidHash(
                                "Unrecognized or missing paramter",
                            ))
                        }
                    }
                }

                HashStates::PKey => {
                    if has_p {
                        return Err(Argon2idError::InvalidHash("Duplicate key 'p'"));
                    }

                    state = match c {
                        '=' => HashStates::PEquals,
                        _ => return Err(Argon2idError::InvalidHash("Missing 'p' paramter")),
                    }
                }

                HashStates::PEquals => {
                    p = i..(i + 1);
                    state = HashStates::PValue;
                }

                HashStates::PValue => {
                    if c == ',' {
                        state = HashStates::PComplete;
                    } else if c == '$' && has_m && has_t {
                        state = HashStates::Salt;
                    } else {
                        p.end += 1;
                    }
                }

                HashStates::PComplete => {
                    has_p = true;

                    state = match c {
                        'm' => HashStates::MKey,
                        't' => HashStates::TKey,
                        _ => {
                            return Err(Argon2idError::InvalidHash(
                                "Unrecognized or missing parameter",
                            ))
                        }
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
                        return Err(Argon2idError::InvalidHash("Missing hash after salt"));
                    }

                    hash = String::from(&parameterized_hash[i..]);
                    state = HashStates::Hash;

                    break;
                }

                // Should break out of loop before this point
                HashStates::Hash => unreachable!(),
            }
        }

        if std::mem::discriminant(&state) != std::mem::discriminant(&HashStates::Hash) {
            return Err(Argon2idError::InvalidHash("Hash is incomplete"));
        }

        salt.shrink_to_fit();

        let v: u32 = match parameterized_hash[v].parse() {
            Ok(v) => v,
            Err(_) => return Err(Argon2idError::InvalidHash("Invalid version")),
        };

        let mem_cost_kib: u32 = match parameterized_hash[m].parse() {
            Ok(m) => m,
            Err(_) => return Err(Argon2idError::InvalidHash("Invalid m")),
        };

        let iterations: u32 = match parameterized_hash[t].parse() {
            Ok(t) => t,
            Err(_) => return Err(Argon2idError::InvalidHash("Invalid t")),
        };

        let threads: u32 = match parameterized_hash[p].parse() {
            Ok(p) => p,
            Err(_) => return Err(Argon2idError::InvalidHash("Invalid p")),
        };

        Ok(TokenizedHash {
            v,
            mem_cost_kib,
            iterations,
            threads,
            b64_salt: salt,
            b64_hash: hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_hash_into_hash_string() {
        let hash = Hash {
            mem_cost_kib: 128,
            iterations: 3,
            threads: 2,
            salt: vec![1, 2, 3, 4, 5, 6, 7, 8],
            hash: base64::decode_config(
                "ypJ3pKxN4aWGkwMv0TOb08OIzwrfK1SZWy64vyTLKo8",
                base64::STANDARD_NO_PAD,
            )
            .unwrap()
            .to_vec(),
        };

        assert_eq!(hash.to_string(),
                   String::from(
                       "$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg$ypJ3pKxN4aWGkwMv0TOb08OIzwrfK1SZWy64vyTLKo8"
                   ));
    }

    #[test]
    fn test_hash_from_str() {
        let hash = Hash::from_str(
            "$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        )
        .unwrap();

        assert_eq!(hash.mem_cost_kib, 128);
        assert_eq!(hash.iterations, 3);
        assert_eq!(hash.threads, 2);
        assert_eq!(
            hash.salt,
            base64::decode_config("AQIDBAUGBwg", base64::STANDARD_NO_PAD).unwrap()
        );
        assert_eq!(
            hash.hash,
            base64::decode_config(
                "7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
                base64::STANDARD_NO_PAD
            )
            .unwrap()
        );

        let hash = Hash::from_str(
            "$argon2id$v=19$t=3,m=128,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        )
        .unwrap();

        assert_eq!(hash.mem_cost_kib, 128);
        assert_eq!(hash.iterations, 3);
        assert_eq!(hash.threads, 2);
        assert_eq!(
            hash.salt,
            base64::decode_config("AQIDBAUGBwg", base64::STANDARD_NO_PAD).unwrap()
        );
        assert_eq!(
            hash.hash,
            base64::decode_config(
                "7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
                base64::STANDARD_NO_PAD
            )
            .unwrap()
        );

        let hash = Hash::from_str(
            "$argon2id$v=19$p=2,m=128,t=3$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        )
        .unwrap();

        assert_eq!(hash.mem_cost_kib, 128);
        assert_eq!(hash.iterations, 3);
        assert_eq!(hash.threads, 2);
        assert_eq!(
            hash.salt,
            base64::decode_config("AQIDBAUGBwg", base64::STANDARD_NO_PAD).unwrap()
        );
        assert_eq!(
            hash.hash,
            base64::decode_config(
                "7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
                base64::STANDARD_NO_PAD
            )
            .unwrap()
        );

        let hash = Hash::from_str(
            "$argon2id$v=19$t=3,p=2,m=128$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        )
        .unwrap();

        assert_eq!(hash.mem_cost_kib, 128);
        assert_eq!(hash.iterations, 3);
        assert_eq!(hash.threads, 2);
        assert_eq!(
            hash.salt,
            base64::decode_config("AQIDBAUGBwg", base64::STANDARD_NO_PAD).unwrap()
        );
        assert_eq!(
            hash.hash,
            base64::decode_config(
                "7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
                base64::STANDARD_NO_PAD
            )
            .unwrap()
        );
    }

    #[test]
    fn test_invalid_hash_from_str() {
        let hash = Hash::from_str(
            "$argon2id$v=19$m=128,t=3,p=2,$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$t=3,m=128,p=2,m=128$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc"
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2i$v=19$p=2m=128,t=3$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$p=2m=128,t=3$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$t=3,p=2,m=128$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2i$v=19$m=128,t=3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$m=128,t=3,p=2AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=18$m=128,t=3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$m=128,t3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc$",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str("$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg$$");

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$m=128,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$t=2,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$t=2,m=128$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());
    }

    #[test]
    fn test_hash_auth_string() {
        let auth_string = "@Pa$$20rd-Test";

        let key = [1u8; 32];
        let hash_builder = Hasher::default()
            .salt_length(16)
            .hash_length(32)
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .secret(Secret::using_bytes(&key));

        let hash = hash_builder.hash(auth_string).unwrap().to_string();

        assert!(!hash.contains(auth_string));
        assert!(Hash::from_str(&hash)
            .unwrap()
            .verify_with_secret(auth_string, Secret::using_bytes(&key)));
    }

    #[test]
    fn test_hash_auth_string_no_secret() {
        let auth_string = "@Pa$$20rd-Test";

        let hash = Hasher::default()
            .salt_length(16)
            .hash_length(32)
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(auth_string)
            .unwrap()
            .to_string();

        assert!(!hash.contains(auth_string));
        assert!(Hash::from_str(&hash).unwrap().verify(auth_string));
    }

    #[test]
    fn test_verify_hash() {
        let auth_string = "@Pa$$20rd-Test";

        let key = [0u8; 32];
        let hash_builder = Hasher::default()
            .salt_length(16)
            .hash_length(32)
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .secret(Secret::using_bytes(&key));

        let hash = hash_builder.hash(auth_string).unwrap().to_string();

        assert!(Hash::from_str(&hash)
            .unwrap()
            .verify_with_secret(auth_string, Secret::using_bytes(&key)));
    }

    #[test]
    fn test_verify_incorrect_auth_string() {
        let auth_string = "@Pa$$20rd-Test";

        let key = [0u8; 32];
        let hash_builder = Hasher::default()
            .salt_length(16)
            .hash_length(32)
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .secret(Secret::using_bytes(&key));

        let hash = hash_builder.hash(auth_string).unwrap().to_string();

        assert!(Hash::from_str(&hash)
            .unwrap()
            .verify_with_secret(auth_string, Secret::using_bytes(&key)));
    }

    #[test]
    fn test_verify_incorrect_key() {
        let auth_string = "@Pa$$20rd-Test";

        let key = [0u8; 32];
        let hash_builder = Hasher::default()
            .salt_length(16)
            .hash_length(32)
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .secret(Secret::using_bytes(&key));

        let hash = hash_builder.hash(auth_string).unwrap().to_string();

        assert!(Hash::from_str(&hash)
            .unwrap()
            .verify_with_secret(auth_string, Secret::using_bytes(&key)));
    }
}
