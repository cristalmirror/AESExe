use crate::cipher::{BlockCipher, validate_key};
use std::io;

pub struct ChaCha20 {
    state: [u32; 16],
}

impl ChaCha20 {
    pub fn new(key: &[u8]) -> io::Result<Self> {
        validate_key(key, 32)?;
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
        for (i, c) in key.chunks_exact(4).enumerate() {
            state[4 + i] = u32::from_le_bytes(c.try_into().unwrap());
        }
        state[12] = 1; // Mantiene el formato histórico: nonce cero, contador inicial 1.
        Ok(Self { state })
    }
    fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(7);
    }
}

impl BlockCipher for ChaCha20 {
    fn block_size(&self) -> usize {
        64
    }
    fn encrypt_block(&mut self, input: &[u8], output: &mut [u8]) {
        let initial = self.state;
        let mut work = initial;
        for _ in 0..10 {
            Self::qr(&mut work, 0, 4, 8, 12);
            Self::qr(&mut work, 1, 5, 9, 13);
            Self::qr(&mut work, 2, 6, 10, 14);
            Self::qr(&mut work, 3, 7, 11, 15);
            Self::qr(&mut work, 0, 5, 10, 15);
            Self::qr(&mut work, 1, 6, 11, 12);
            Self::qr(&mut work, 2, 7, 8, 13);
            Self::qr(&mut work, 3, 4, 9, 14);
        }
        for i in 0..16 {
            work[i] = work[i].wrapping_add(initial[i]);
            for j in 0..4 {
                output[i * 4 + j] = input[i * 4 + j] ^ work[i].to_le_bytes()[j];
            }
        }
        self.state[12] = self.state[12].wrapping_add(1);
    }
    fn decrypt_block(&mut self, input: &[u8], output: &mut [u8]) {
        self.encrypt_block(input, output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc_block() {
        let key: Vec<u8> = (0..32).collect();
        let mut c = ChaCha20::new(&key).unwrap();
        let mut out = [0; 64];
        c.encrypt_block(&[0; 64], &mut out);
        assert_eq!(
            &out[..16],
            &[
                0x18, 0xb8, 0x42, 0x31, 0xad, 0xe6, 0xa6, 0xd1, 0x13, 0x61, 0x5c, 0x61, 0xaf, 0x43,
                0x4e, 0x27
            ]
        );
    }
}
