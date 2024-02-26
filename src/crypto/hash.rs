use sha3::{Digest, Sha3_256};

pub fn blake2b(data: &[u8]) -> Vec<u8> {
    let mut h = vec![0; sodium_sys::crypto_generichash_BYTES as usize];

    unsafe {
        sodium_sys::crypto_generichash(
            h.as_mut_ptr(),
            sodium_sys::crypto_generichash_BYTES as usize,
            data.as_ptr(),
            data.len() as u64,
            std::ptr::null(),
            0,
        );
    }

    h
}

pub fn sha3(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
