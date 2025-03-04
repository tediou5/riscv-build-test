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
#[cfg(not(test))]
use alloc::vec::Vec;
use rand_core::RngCore;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub struct Key {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
    rng: EmbeddedRng,
}

impl Key {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.public_key
            .encrypt(&mut self.rng.clone(), Pkcs1v15Encrypt, data)
            .unwrap_or_default()
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.private_key
            .decrypt(Pkcs1v15Encrypt, data)
            .unwrap_or_default()
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

    fn new_key(mut self, bits: usize) -> Key {
        let private_key = RsaPrivateKey::new(&mut self, bits).expect("生成私钥失败");
        let public_key = RsaPublicKey::from(&private_key);
        Key {
            private_key,
            public_key,
            rng: self,
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
///   - a pointer to a new cryptor
/// Note:
///   - the cryptor must be dropped using `drop_cryptor`
#[no_mangle]
pub extern "C" fn new_cryptor(next_u8: extern "C" fn() -> u8) -> *const () {
    let rng = EmbeddedRng::new(next_u8);
    let key = rng.new_key(2048);
    Box::into_raw(Box::new(key)) as *const ()
}

/// Parameters:
///   - ptr: a pointer to a cryptor
///   - data: a pointer to the data to be encrypted
///   - len: the length of the data
///   - out_len: a pointer to the length of the encrypted data, 0 if failed
/// Returns:
///   - a pointer of the encrypted data
#[no_mangle]
pub extern "C" fn encrypt(
    ptr: *const (),
    data: *const u8,
    len: usize,
    out_len: *mut usize,
) -> *const u8 {
    let key = unsafe { &*(ptr as *const Key) };
    let data = unsafe { core::slice::from_raw_parts(data, len) };
    let encrypted = key.encrypt(data).into_boxed_slice();
    unsafe { *out_len = encrypted.len() };
    Box::into_raw(encrypted) as *const u8
}

/// Parameters:
///   - ptr: a pointer to a cryptor
///   - data: a pointer to the data to be decrypted
///   - len: the length of the data
///   - out_len: a pointer to the length of the decrypted data, 0 if failed
/// Returns:
///   - a pointer of the decrypted data
#[no_mangle]
pub extern "C" fn decrypt(
    ptr: *const (),
    data: *const u8,
    len: usize,
    out_len: *mut usize,
) -> *const u8 {
    let key = unsafe { &*(ptr as *const Key) };
    let data = unsafe { core::slice::from_raw_parts(data, len) };
    let decrypted = key.decrypt(data);
    unsafe { *out_len = decrypted.len() };
    Box::into_raw(decrypted.into_boxed_slice()) as *const u8
}

/// Note:
///   - the cryptor must be dropped using this function
#[no_mangle]
pub extern "C" fn drop_cryptor(ptr: *const ()) {
    unsafe {
        let _ = Box::from_raw(ptr as *mut Key);
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn next_u8() -> u8 {
        rand::random()
    }

    #[test]
    fn test_encrypt_decrypt() {
        let rng = EmbeddedRng::new(next_u8);
        let key = rng.new_key(1024);
        let msg = b"Hello";
        let encrypted = key.encrypt(msg);
        let decrypted = key.decrypt(&encrypted);
        assert_eq!(msg.to_vec(), decrypted);
    }

    #[test]
    fn test_c_api_encrypt_decrypt() {
        let key_ptr = new_cryptor(next_u8);
        let msg = b"Hello";
        let mut encrypted_len = 0;
        let mut decrypted_len = 0;

        let encrypted = encrypt(key_ptr, msg.as_ptr(), msg.len(), &mut encrypted_len);
        let decrypted = decrypt(key_ptr, encrypted, encrypted_len, &mut decrypted_len);
        drop_cryptor(key_ptr);
        assert_eq!(msg.to_vec(), unsafe {
            Vec::from_raw_parts(decrypted as *mut u8, decrypted_len, decrypted_len)
        });
    }
}
