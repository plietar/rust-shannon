#![feature(libc)]

extern crate shannon_sys as shn;
extern crate libc;

use shn::*;
use libc::c_int;

pub struct Shannon {
    ctx: shn_ctx
}

impl Shannon {
    pub fn new(key: &[u8]) -> Shannon {
        let ctx = unsafe {
            let mut ctx = ::std::mem::uninitialized();
            shn_key(&mut ctx, key.as_ptr(), key.len() as c_int);
            ctx
        };

        Shannon {
            ctx: ctx
        }
    }

    pub fn nonce(&mut self, nonce: &[u8]) {
        unsafe {
            shn_nonce(&mut self.ctx, nonce.as_ptr(), nonce.len() as c_int);
        }
    }

    pub fn stream(&mut self, buf: &mut [u8]) {
        unsafe {
            shn_stream(&mut self.ctx, buf.as_mut_ptr(), buf.len() as c_int);
        }
    }

    pub fn maconly(&mut self, buf: &[u8]) {
        unsafe {
            shn_maconly(&mut self.ctx, buf.as_ptr(), buf.len() as c_int);
        }
    }

    pub fn encrypt(&mut self, buf: &mut [u8]) {
        unsafe {
            shn_encrypt(&mut self.ctx, buf.as_mut_ptr(), buf.len() as c_int);
        }
    }

    pub fn decrypt(&mut self, buf: &mut [u8]) {
        unsafe {
            shn_decrypt(&mut self.ctx, buf.as_mut_ptr(), buf.len() as c_int);
        }
    }

    pub fn finish(&mut self, count: u32) -> Vec<u8> {
        let mut mac = Vec::with_capacity(count as usize);
        unsafe {
            shn_finish(&mut self.ctx, mac.as_mut_ptr(), mac.len() as c_int);
            mac.set_len(count as usize);
        }

        mac
    }
}

