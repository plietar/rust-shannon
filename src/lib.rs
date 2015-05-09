#![feature(libc)]

extern crate shannon_sys as shn;
extern crate libc;
extern crate byteorder;
extern crate readall;

use shn::*;
use libc::c_int;
use byteorder::{BigEndian,ByteOrder};
use readall::ReadAllExt;
use std::io;

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
            shn_finish(&mut self.ctx, mac.as_mut_ptr(), count as c_int);
            mac.set_len(count as usize);
        }

        mac
    }
}

pub struct ShannonStream<S : io::Read + io::Write> {
    stream: S,

    send_nonce: u32,
    send_cipher: Shannon,

    recv_nonce: u32,
    recv_cipher: Shannon,
}

fn get_nonce(n: u32) -> [u8; 4] {
    let mut nonce = [0; 4];
    BigEndian::write_u32(&mut nonce, n);
    nonce
}

impl <S : io::Read + io::Write> ShannonStream<S> {
    pub fn new(stream: S, send_key: &[u8], recv_key: &[u8]) -> ShannonStream<S> {
        let mut s = ShannonStream {
            stream: stream,

            send_nonce: 0,
            send_cipher: Shannon::new(send_key),

            recv_nonce: 0,
            recv_cipher: Shannon::new(recv_key),
        };

        // Set the nonces so we are ready to go
        s.send_cipher.nonce(&get_nonce(s.send_nonce));
        s.recv_cipher.nonce(&get_nonce(s.recv_nonce));
        s
    }

    pub fn finish_send(&mut self) -> io::Result<()> {
        let mac = self.send_cipher.finish(4);
        try!(self.stream.write(&mac));

        // Get ready for next send
        self.send_nonce += 1;
        self.send_cipher.nonce(&get_nonce(self.send_nonce));

        Ok(())
    }

    pub fn finish_recv(&mut self) -> io::Result<()> {
        let mut mac = [0; 4];
        try!(self.stream.read_all(&mut mac));

        let mac2 = self.recv_cipher.finish(4);

        if mac2 != mac {
            return Err(io::Error::new(io::ErrorKind::Other, "MAC mismatch"));
        }

        // Get ready for next recv
        self.recv_nonce += 1;
        self.recv_cipher.nonce(&get_nonce(self.recv_nonce));

        Ok(())
    }
}

impl <S : io::Read + io::Write> io::Read for ShannonStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = try!(self.stream.read(buf));

        self.recv_cipher.decrypt(&mut buf[..count]);

        Ok(count)
    }
}

impl <S : io::Read + io::Write> io::Write for ShannonStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut data = buf.to_vec();
        self.send_cipher.encrypt(&mut data);
        self.stream.write(&data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

