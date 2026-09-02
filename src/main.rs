/* ################# AESExe V 0.4.0 #################
    Archive: main.rs
    Version: 0.4.0
    License: GPL-v3.0
    #################################################
    
    This code is part of AESExe, a software to cipher archive in local mode or web mode.

    This software was writed in C++ first time, but was refactor in rust be cause is more 
    simple compilation configure and securice memory.
*/
use aesexe::{aes::Aes, chacha20::ChaCha20, cipher::BlockCipher, keys, server, stream};
use std::{env, fs::File, io, path::Path, process::ExitCode};

/* The --help options to print the menu mode and use form */
fn help(p: &str) {
    println!(
        "AESExe — cifrado de archivos en Rust\n\nUso:\n  {p} --key <aes128|aes192|aes256|chacha20>\n  {p} enc|dec <entrada> <clave> <salida>\n  {p} enc-192|dec-192 <entrada> <clave> <salida>\n  {p} enc-256|dec-256 <entrada> <clave> <salida>\n  {p} enc-cc20|dec-cc20 <entrada> <clave> <salida>\n  {p} ser <IP> <PUERTO>\n  {p} --help"
    );
}

/* 
 * Resept mode args (mode, input file, key and output file) and make
 * the key object and the the cipher object depending on what 
 * algorithm and what type
 */
fn file_mode(mode: &str, input: &str, key_path: &str, output: &str) -> io::Result<()> {
    let key = keys::load(Path::new(key_path))?;
    let (expected, mut cipher, encrypt): (usize, Box<dyn BlockCipher>, bool) = match mode {
        "enc" => (16, Box::new(Aes::new(&key)?), true),
        "dec" => (16, Box::new(Aes::new(&key)?), false),
        "enc-192" => (24, Box::new(Aes::new(&key)?), true),
        "dec-192" => (24, Box::new(Aes::new(&key)?), false),
        "enc-256" => (32, Box::new(Aes::new(&key)?), true),
        "dec-256" => (32, Box::new(Aes::new(&key)?), false),
        "enc-cc20" => (32, Box::new(ChaCha20::new(&key)?), true),
        "dec-cc20" => (32, Box::new(ChaCha20::new(&key)?), false),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "modo desconocido",
            ));
        }
    };
    /* Error if not typing the key archive argument */
    if key.len() != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("el modo {mode} requiere una clave de {expected} bytes"),
        ));
    }
    let mut source = File::open(input)?;
    let mut target = File::create(output)?;
    stream::process(&mut *cipher, &mut source, &mut target, encrypt)
}

/* 
 * This operation is a loader the parts of code depending of mode sending.
 * In hindsight this run function, working like a main function.
 */
fn run() -> io::Result<()> {
    let a: Vec<String> = env::args().collect();
    let p = &a[0];
    match a.as_slice() {
        /* Print Menu Mode */
        [_, f] if f == "--help" => {
            help(p);
            Ok(())
        }
        /* Key Maker Mode*/
        [_, f, algo] if f == "--key" => {
            let path = keys::generate_file(algo)?;
            println!("[AESExe] clave generada: {path}");
            Ok(())
        }
        /* Server Mode set */
        [_, m, ip, port] if m == "ser" => server::run(
            ip,
            port.parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "puerto inválido"))?,
        ),
        /* Local mode for defect */
        [_, m, i, k, o] => {
            file_mode(m, i, k, o)?;
            println!("[AESExe] operación completada: {o}");
            Ok(())
        }
        _ => { /* Invalid Error Mode */
            help(p);
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "argumentos inválidos",
            ))
        }
    }
}
/* The fucking main function, no more */
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}
