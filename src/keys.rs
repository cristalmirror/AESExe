/* ################# AESExe V 0.4.0 #################
   Archive: keys.rs
   Version: 0.4.0
   License: GPL-v3.0
  ##################################################

  This code make the keys need...
*/

use rand::rngs::OsRng;
use rand::TryRngCore;
use std::{fs, io, path::Path};

pub fn key_size(algo: &str) -> io::Result<usize> {
    match algo {
        "aes128" => Ok(16),
        "aes192" => Ok(24),
        "aes256" | "chacha20" => Ok(32),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("algoritmo no soportado: {algo}"),
        )),
    }
}

pub fn generate(algo: &str) -> io::Result<Vec<u8>> {
    let mut key = vec![0; key_size(algo)?];
    OsRng.try_fill_bytes(&mut key).map_err(io::Error::other)?;
    Ok(key)
}

pub fn generate_file(algo: &str) -> io::Result<String> {
    let key = generate(algo)?;
    let name = match algo {
        "aes128" => "keyAES128.bin".to_owned(),
        "aes192" => "keyAES192.bin".to_owned(),
        _ => format!("key{algo}.bin"),
    };
    fs::write(&name, key)?;
    Ok(name)
}

pub fn load(path: &Path) -> io::Result<Vec<u8>> {
    fs::read(path)
}
