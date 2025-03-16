#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(not(test))]
extern crate alloc;
#[cfg(not(test))]
extern crate wee_alloc;

#[cfg(not(test))]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[cfg(not(test))]
use alloc::boxed::Box;
use k256::schnorr::{
    signature::{Signer, Verifier},
    SigningKey, VerifyingKey,
};
use rand_core::RngCore;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub struct Key {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Key {
    fn sign(&self, data: &[u8; 32]) -> [u8; 64] {
        let signature = self.signing_key.sign(data); // returns `k256::schnorr::Signature`
        signature.to_bytes()
    }

    fn verify(&self, data: &[u8; 32], signature_bytes: &[u8; 64]) -> bool {
        let Ok(signature) = k256::schnorr::Signature::try_from((*signature_bytes).as_slice())
        else {
            return false;
        };
        self.verifying_key.verify(data, &signature).is_ok()
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct EmbeddedRng {
    next_u8: extern "C" fn() -> u8,
}

impl EmbeddedRng {
    fn new(next_u8: extern "C" fn() -> u8) -> Self {
        Self { next_u8 }
    }

    fn new_key(mut self) -> Key {
        let signing_key = SigningKey::random(&mut self);
        let verifying_key = *signing_key.verifying_key();
        Key {
            signing_key,
            verifying_key,
        }
    }
}

impl RngCore for EmbeddedRng {
    fn next_u32(&mut self) -> u32 {
        let mut u32_bytes = [0u8; 4];
        self.fill_bytes(&mut u32_bytes);
        u32::from_le_bytes(u32_bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut u64_bytes = [0u8; 8];
        self.fill_bytes(&mut u64_bytes);
        u64::from_le_bytes(u64_bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = (self.next_u8)();
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for EmbeddedRng {}

/// Parameters:
///   - next_u8: a function pointer to a function that returns a random u8
/// Returns:
///   - a pointer to a new signature
/// Note:
///   - the signature must be dropped using `drop_signature`
#[no_mangle]
pub extern "C" fn new_signature(next_u8: extern "C" fn() -> u8) -> *const () {
    let rng = EmbeddedRng::new(next_u8);
    let key = rng.new_key();
    Box::into_raw(Box::new(key)) as *const ()
}

/// Parameters:
///   - ptr: a pointer to a cryptor
///   - data: message to be signed
///   - out: a pointer to the length of the encrypted data, 0 if failed
/// Returns:
///   - the signature data
#[no_mangle]
pub extern "C" fn sign(ptr: *const (), data: &[u8; 32], out: *mut [u8; 64]) {
    let key = unsafe { &*(ptr as *const Key) };
    let signature = key.sign(data);
    let out = unsafe { &mut *out };
    out.copy_from_slice(&signature);
}

/// Parameters:
///   - ptr: a pointer to a cryptor
///   - data: message to be verified
///   - signature_bytes: signature to be verified
/// Returns:
///   - true if the signature is valid, false otherwise
#[no_mangle]
pub extern "C" fn verify(ptr: *const (), data: &[u8; 32], signature_bytes: &[u8; 64]) -> bool {
    let key = unsafe { &*(ptr as *const Key) };
    key.verify(data, signature_bytes)
}

/// Note:
///   - the signature must be dropped using this function
#[no_mangle]
pub extern "C" fn drop_signature(ptr: *const ()) {
    unsafe {
        let _ = Box::from_raw(ptr as *mut Key);
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    extern "C" fn next_u8() -> u8 {
        rand::random()
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = EmbeddedRng::new(next_u8);
        let mut message = [0u8; 32];
        rng.fill(&mut message);
        let key = rng.new_key();
        let signature = key.sign(&message);
        assert!(key.verify(&message, &signature));
    }

    #[test]
    fn test_c_api_encrypt_decrypt() {
        let key_ptr = new_signature(next_u8);

        let mut signature = [0u8; 64];
        let mut rng = EmbeddedRng::new(next_u8);
        let mut message = [0u8; 32];
        rng.fill(&mut message);

        sign(key_ptr, &message, &mut signature);
        assert!(verify(key_ptr, &message, &signature));
    }
}
