use crate::cipher::BlockCipher;
use std::io::{self, Read, Write};

pub fn process(
    cipher: &mut dyn BlockCipher,
    input: &mut dyn Read,
    output: &mut dyn Write,
    encrypt: bool,
) -> io::Result<()> {
    let size = cipher.block_size();
    let mut block = vec![0u8; size];
    loop {
        let mut read = 0;
        while read < size {
            let n = input.read(&mut block[read..])?;
            if n == 0 {
                break;
            }
            read += n
        }
        if read == 0 {
            break;
        }
        block[read..].fill(0);
        let mut result = vec![0; size];
        if encrypt {
            cipher.encrypt_block(&block, &mut result)
        } else {
            cipher.decrypt_block(&block, &mut result)
        }
        output.write_all(&result)?;
        if read < size {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct X;
    impl BlockCipher for X {
        fn block_size(&self) -> usize {
            4
        }
        fn encrypt_block(&mut self, i: &[u8], o: &mut [u8]) {
            for n in 0..4 {
                o[n] = i[n] ^ 1
            }
        }
        fn decrypt_block(&mut self, i: &[u8], o: &mut [u8]) {
            self.encrypt_block(i, o)
        }
    }
    #[test]
    fn pads_like_legacy() {
        let mut c = X;
        let mut out = vec![];
        process(&mut c, &mut &b"abc"[..], &mut out, true).unwrap();
        assert_eq!(out, b"`cb\x01")
    }
}
