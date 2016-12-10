#![allow(non_snake_case, non_camel_case_types)]

extern crate byteorder;

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::io;

const N: usize = 16;
const FOLD: usize = N;
const INITKONST: u32 = 0x6996c53ai32 as (u32);
const KEYP: usize = 13;

#[derive(Clone)]
pub struct Shannon {
    pub R: [u32; N],
    pub CRC: [u32; N],
    pub initR: [u32; N],
    pub konst: u32,
    pub sbuf: u32,
    pub mbuf: u32,
    pub nbuf: usize,
}

fn sbox1(mut w: u32) -> u32 {
    w = w ^ (w << 5i32 | w >> 32i32 - 5i32 | (w << 7i32 | w >> 32i32 - 7i32));
    w = w ^ (w << 19i32 | w >> 32i32 - 19i32 | (w << 22i32 | w >> 32i32 - 22i32));
    w
}

fn sbox2(mut w: u32) -> u32 {
    w = w ^ (w << 7i32 | w >> 32i32 - 7i32 | (w << 22i32 | w >> 32i32 - 22i32));
    w = w ^ (w << 5i32 | w >> 32i32 - 5i32 | (w << 19i32 | w >> 32i32 - 19i32));
    w
}

fn ROTL(w: u32, x: usize) -> u32 {
    (w << x) | (w >> (32 - x))
}

impl Shannon {
    // initialise to known state
    pub fn new(key: &[u8]) -> Shannon {
        let mut c = Shannon {
            R: [0u32; N],
            CRC: [0u32; N],
            initR: [0u32; N],
            konst: INITKONST,
            sbuf: 0,
            mbuf: 0,
            nbuf: 0,
        };

        // Register initialised to Fibonacci numbers; Counter zeroed.
        c.R[0] = 1;
        c.R[1] = 1;
        for i in 2..16 {
            c.R[i] = c.R[i - 1] + c.R[i - 2];
        }

        c.loadkey(key);
        c.genkonst();
        c.savestate();

        c
    }

    // Save the current register state
    fn savestate(&mut self) {
        self.initR = self.R;
    }

    // initialise to previously saved register state
    fn reloadstate(&mut self) {
        self.R = self.initR;
    }

    // Initialise "konst"
    fn genkonst(&mut self) {
        self.konst = self.R[0];
    }

    // cycle the contents of the register and calculate output word in c->sbuf.
    fn cycle(&mut self) {
        // nonlinear feedback function
        let mut t = self.R[12] ^ self.R[13] ^ self.konst;
        t = sbox1(t) ^ ROTL(self.R[0], 1);

        // shift register
        for i in 1..N {
            self.R[i - 1] = self.R[i];
        }
        self.R[N - 1] = t;
        t = sbox2(self.R[2] ^ self.R[15]);
        self.R[0] ^= t;
        self.sbuf = t ^ self.R[8] ^ self.R[12];
    }

    // extra nonlinear diffusion of register for key and MAC
    fn diffuse(&mut self) {
        for _ in 0..FOLD {
            self.cycle();
        }
    }

    // Common actions for loading key material
    // Allow non-word-multiple key and nonce material.
    // Note also initializes the CRC register as a side effect.
    fn loadkey(&mut self, key: &[u8]) {
        // start folding in key
        for word in key.chunks(4) {
            if word.len() == 4 {
                self.R[KEYP] ^= LittleEndian::read_u32(word);
            } else {
                // if there were any extra key bytes, zero pad to a word
                let mut xtra = [0u8; 4];
                for i in 0..word.len() {
                    xtra[i] = word[i];
                }
                self.R[KEYP] ^= LittleEndian::read_u32(&xtra);
            }
            self.cycle();
        }

        // also fold in the length of the key
        self.R[KEYP] ^= key.len() as u32;
        self.cycle();

        // save a copy of the register
        self.CRC = self.R;

        // now diffuse
        self.diffuse();

        // now xor the copy back -- makes key loading irreversible
        for i in 0..16 {
            self.R[i] ^= self.CRC[i];
        }
    }

    pub fn nonce(&mut self, nonce: &[u8]) {
        self.reloadstate();
        self.konst = INITKONST;
        self.loadkey(nonce);
        self.genkonst();
        self.nbuf = 0;
    }

    // Accumulate a CRC of input words, later to be fed into MAC.
    // This is actually 32 parallel CRC-16s, using the IBM CRC-16
    // polynomial x^16 + x^15 + x^2 + 1.
    fn crcfunc(&mut self, i: u32) {
        let t = self.CRC[0] ^ self.CRC[2] ^ self.CRC[15] ^ i;
        for j in 1..N {
            self.CRC[j - 1] = self.CRC[j];
        }
        self.CRC[N - 1] = t;
    }

    // Normal MAC word processing: do both stream register and CRC.
    fn macfunc(&mut self, i: u32) {
        self.crcfunc(i);
        self.R[KEYP] ^= i;
    }

    fn process<F, G>(&mut self, buf: &mut [u8], full_word: F, partial: G)
        where F: Fn(&mut Self, &mut u32),
              G: Fn(&mut Self, &mut u8)
    {
        // handle any previously buffered bytes
        let mut buf = buf.into_iter();
        if self.nbuf != 0 {
            while self.nbuf > 0 {
                if let Some(b) = buf.next() {
                    partial(self, b);
                    self.nbuf -= 8;
                } else {
                    // not a whole word yet
                    return;
                }

                // LFSR already cycled
                let m = self.mbuf;
                self.macfunc(m);
            }
        }

        let buf = buf.into_slice();

        // handle whole words
        let len = buf.len() & !0x3;
        let (buf, extra) = buf.split_at_mut(len);
        for word in buf.chunks_mut(4) {
            self.cycle();
            let mut t = LittleEndian::read_u32(word);
            full_word(self, &mut t);
            LittleEndian::write_u32(word, t);
        }

        // handle any trailing bytes
        if extra.len() > 0 {
            self.cycle();
            self.mbuf = 0;
            self.nbuf = 32;
            for b in extra.into_iter() {
                partial(self, b);
                self.nbuf -= 8;
            }
        }
    }

    // Combined MAC and encryption.
    // Note that plaintext is accumulated for MAC.
    pub fn encrypt(&mut self, buf: &mut [u8]) {
        self.process(buf,
                     |ctx, word| {
                         ctx.macfunc(*word);
                         *word ^= ctx.sbuf;
                     },
                     |ctx, b| {
                         ctx.mbuf ^= (*b as u32) << (32 - ctx.nbuf);
                         *b ^= ((ctx.sbuf >> (32 - ctx.nbuf)) & 0xFF) as u8;
                     });
    }

    // Combined MAC and decryption.
    // Note that plaintext is accumulated for MAC.
    pub fn decrypt(&mut self, buf: &mut [u8]) {
        self.process(buf,
                     |ctx, word| {
                         *word ^= ctx.sbuf;
                         ctx.macfunc(*word);
                     },
                     |ctx, b| {
                         *b ^= ((ctx.sbuf >> (32 - ctx.nbuf)) & 0xFF) as u8;
                         ctx.mbuf ^= (*b as u32) << (32 - ctx.nbuf);
                     });
    }

    // Having accumulated a MAC, finish processing and return it.
    // Note that any unprocessed bytes are treated as if
    // they were encrypted zero bytes, so plaintext (zero) is accumulated.
    pub fn finish(&mut self, buf: &mut [u8]) {
        // handle any previously buffered bytes
        if self.nbuf != 0 {
            let m = self.mbuf;
            self.macfunc(m);
        }

        // perturb the MAC to mark end of input.
        // Note that only the stream register is updated, not the CRC. This is an
        // action that can't be duplicated by passing in plaintext, hence
        // defeating any kind of extension attack.
        //
        self.cycle();
        self.R[KEYP] ^= INITKONST ^ ((self.nbuf as u32) << 3);
        self.nbuf = 0;

        // now add the CRC to the stream register and diffuse it
        for i in 0..N {
            self.R[i] ^= self.CRC[i];
        }
        self.diffuse();

        // produce output from the stream buffer
        for word in buf.chunks_mut(4) {
            self.cycle();
            if word.len() == 4 {
                LittleEndian::write_u32(word, self.sbuf);
            } else {
                for (b, i) in word.into_iter().zip(0..) {
                    *b = ((self.sbuf >> (8 * i)) & 0xFF) as u8;
                }
            }
        }
    }

    pub fn nonce_u32(&mut self, n: u32) {
        let mut nonce = [0u8; 4];
        BigEndian::write_u32(&mut nonce, n);
        self.nonce(&nonce);
    }

    pub fn check_mac(&mut self, expected: &[u8]) -> io::Result<()> {
        let mut actual = vec![0u8; expected.len()];
        self.finish(&mut actual);

        if actual != expected {
            Err(io::Error::new(io::ErrorKind::Other, "MAC mismatch"))
        } else {
            Ok(())
        }
    }
}
