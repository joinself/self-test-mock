pub fn vec(size: usize) -> Vec<u8> {
    let mut random_buf = vec![0_u8; size].into_boxed_slice();

    unsafe {
        sodium_sys::randombytes_buf(random_buf.as_mut_ptr() as *mut libc::c_void, size);
    }

    random_buf.to_vec()
}

pub fn read_bytes(random_buf: &mut [u8]) {
    unsafe {
        sodium_sys::randombytes_buf(
            random_buf.as_mut_ptr() as *mut libc::c_void,
            random_buf.len(),
        );
    }
}
