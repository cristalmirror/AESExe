# AESExe – cifrado en Rust

Herramienta de cifrado implementada íntegramente en Rust. Incluye AES-128,
AES-192, AES-256, ChaCha20, una CLI y un servidor web HTTPS.

## Compilación

Requiere Rust estable y Cargo.

```bash
cargo build
```

El ejecutable de desarrollo queda disponible en `target/debug/aesexe`.

## Uso

Genera una clave AES de 128 bits:

```bash
./target/debug/aesexe --key aes128
```

Cifra un archivo con AES-128:

```bash
./target/debug/aesexe enc archivo.txt keyAES128.bin cifrado.aes
```

Descifra un archivo con AES-128:

```bash
./target/debug/aesexe dec cifrado.aes keyAES128.bin resultado.txt
```

Cifra un archivo con AES-192:

```bash
./target/debug/aesexe enc-192 archivo.txt keyAES192.bin cifrado.aes
```

Descifra un archivo con AES-192:

```bash
./target/debug/aesexe dec-192 cifrado.aes keyAES192.bin resultado.txt
```

Cifra un archivo con AES-256:

```bash
./target/debug/aesexe enc-256 archivo.txt keyaes256.bin cifrado.aes
```

Descifra un archivo con AES-256:

```bash
./target/debug/aesexe dec-256 cifrado.aes keyaes256.bin resultado.txt
```

Cifra un archivo con ChaCha20:

```bash
./target/debug/aesexe enc-cc20 archivo.txt keychacha20.bin cifrado.cc20
```

Descifra un archivo con ChaCha20:

```bash
./target/debug/aesexe dec-cc20 cifrado.cc20 keychacha20.bin resultado.txt
```

El formato conserva compatibilidad con la versión C++: completa el último
bloque con bytes cero. La salida descifrada puede contener ese padding final.

## Servidor web

```bash
./gen-certs.sh 127.0.0.1
./target/debug/aesexe ser 127.0.0.1 8080
```

Luego abrir `https://127.0.0.1:8080`. El certificado autofirmado es solo para
desarrollo.

## Desarrollo

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

- `src/aes.rs`: AES parametrizado por tamaño de clave.
- `src/chacha20.rs`: ChaCha20 compatible con el formato histórico.
- `src/stream.rs`: procesamiento de archivos con memoria constante.
- `src/server.rs`: HTTPS, API JSON y estáticos.
- `src/main.rs`: interfaz de línea de comandos.
