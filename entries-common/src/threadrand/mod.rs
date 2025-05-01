use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, RngCore};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::cell::UnsafeCell;

thread_local! {
    // TODO: Once ed25519_dalek is updated to use rand 0.9, we can update rand, rand_core,
    //       and rand_chacha dependencies to version 0.9 where we can use
    //       ChaCha20Rng::from_os_rng() with the os_rng feature on the rand_chacha crate
    // static RNG: UnsafeCell<ChaCha20Rng> = UnsafeCell::new(ChaCha20Rng::from_os_rng());
    static RNG: UnsafeCell<ChaCha20Rng> = UnsafeCell::new(ChaCha20Rng::from_seed(OsRng.gen()));
}

pub struct SecureRng;

impl SecureRng {
    pub fn get_ref() -> &'static mut ChaCha20Rng {
        unsafe { RNG.with(|rng| &mut *rng.get()) }
    }

    pub fn next_u8() -> u8 {
        RNG.with(|rng| {
            // Only one thread accesses this RNG so this is safe
            unsafe { rand_chacha::rand_core::RngCore::next_u32(&mut *rng.get()) as u8 }
        })
    }

    pub fn next_i8() -> i8 {
        RNG.with(|rng| {
            // Only one thread accesses this RNG so this is safe
            unsafe { rand_chacha::rand_core::RngCore::next_u32(&mut *rng.get()) as i8 }
        })
    }

    pub fn next_u16() -> u16 {
        RNG.with(|rng| {
            // Only one thread accesses this RNG so this is safe
            unsafe { rand_chacha::rand_core::RngCore::next_u32(&mut *rng.get()) as u16 }
        })
    }

    pub fn next_i16() -> i16 {
        RNG.with(|rng| {
            // Only one thread accesses this RNG so this is safe
            unsafe { rand_chacha::rand_core::RngCore::next_u32(&mut *rng.get()) as i16 }
        })
    }

    pub fn next_i32() -> i32 {
        RNG.with(|rng| {
            // Only one thread accesses this RNG so this is safe
            unsafe { rand_chacha::rand_core::RngCore::next_u32(&mut *rng.get()) as i32 }
        })
    }

    pub fn next_i64() -> i64 {
        RNG.with(|rng| {
            // Only one thread accesses this RNG so this is safe
            unsafe { rand_chacha::rand_core::RngCore::next_u64(&mut *rng.get()) as i64 }
        })
    }

    pub fn next_u128() -> u128 {
        RNG.with(|rng| {
            // Only one thread accesses this RNG so this is safe
            let rng_ref = unsafe { &mut *rng.get() };
            let mut bytes = [0u8; 16];
            rand_chacha::rand_core::RngCore::fill_bytes(rng_ref, &mut bytes);
            u128::from_le_bytes(bytes)
        })
    }

    pub fn next_i128() -> i128 {
        RNG.with(|rng| {
            // Only one thread accesses this RNG so this is safe
            let rng_ref = unsafe { &mut *rng.get() };
            let mut bytes = [0u8; 16];
            rand_chacha::rand_core::RngCore::fill_bytes(rng_ref, &mut bytes);
            i128::from_le_bytes(bytes)
        })
    }
}

// TODO: Once ed25519_dalek is updated to use rand 0.9, we can update rand, rand_core, and
//       rand_chacha dependencies to version 0.9 where TryRngCore can be implemented
// impl TryRngCore for SecureRng {
//     type Error = <ChaCha20Rng as TryRngCore>::Error;

//     #[inline]
//     fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
//         RNG.with(|rng| unsafe { (*rng.get()).try_next_u32() })
//     }

//     #[inline]
//     fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
//         RNG.with(|rng| unsafe { (*rng.get()).try_next_u64() })
//     }

//     #[inline]
//     fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
//         RNG.with(|rng| unsafe { (*rng.get()).try_fill_bytes(dest) })
//     }
// }

impl RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        RNG.with(|rng| unsafe { rand_chacha::rand_core::RngCore::next_u32(&mut *rng.get()) })
    }

    fn next_u64(&mut self) -> u64 {
        RNG.with(|rng| unsafe { rand_chacha::rand_core::RngCore::next_u64(&mut *rng.get()) })
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        RNG.with(|rng| unsafe {
            rand_chacha::rand_core::RngCore::fill_bytes(&mut *rng.get(), dest)
        })
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        // try_fill_bytes is infallible for ChaCha20Rng
        RNG.with(|rng| unsafe {
            let _ = (*rng.get()).try_fill_bytes(dest);
        });
        Ok(())
    }
}

impl CryptoRng for SecureRng {}
