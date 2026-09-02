use std::io;

pub trait BlockCipher {
    fn block_size(&self) -> usize;
    fn encrypt_block(&mut self, input: &[u8], output: &mut [u8]);
    fn decrypt_block(&mut self, input: &[u8], output: &mut [u8]);
}

pub fn validate_key(key: &[u8], expected: usize) -> io::Result<()> {
    if key.len() == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("la clave debe tener {expected} bytes; tiene {}", key.len()),
        ))
    }
}
