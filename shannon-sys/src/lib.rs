#![allow(missing_copy_implementations)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![feature(libc)]

extern crate libc;

#[repr(C)]
pub struct shn_ctx {
    R: [libc::uint32_t; 16],
    CRC: [libc::uint32_t; 16],
    initR: [libc::uint32_t; 16],
    konst: libc::uint32_t,
    sbuf: libc::uint32_t,
    mbuf: libc::uint32_t,
    nbuf: libc::c_int,
}

extern {
    pub fn shn_key(c: *mut shn_ctx, key: *const u8, keylen: libc::c_int);
    pub fn shn_nonce(c: *mut shn_ctx, nonce: *const u8, nlen: libc::c_int);
    pub fn shn_stream(c: *mut shn_ctx, buf: *mut u8, nbytes: libc::c_int);
    pub fn shn_maconly(c: *mut shn_ctx, buf: *const u8, nbytes: libc::c_int);
    pub fn shn_encrypt(c: *mut shn_ctx, buf: *mut u8, nbytes: libc::c_int);
    pub fn shn_decrypt(c: *mut shn_ctx, buf: *mut u8, nbytes: libc::c_int);
    pub fn shn_finish(c: *mut shn_ctx, buf: *mut u8, nbytes: libc::c_int);
}

