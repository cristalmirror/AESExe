# AESExe – cifrado en Rust

Herramienta de cifrado implementada íntegramente en Rust. Incluye AES-128,
AES-192, AES-256, ChaCha20, una CLI y un servidor web HTTPS.

## Compilación

Requiere Rust estable y Cargo.

```bash
make
# o: cargo build --release
```

`make` deja el ejecutable compatible en `output/aesexe`.

## Uso

```bash
./output/aesexe --key aes128
./output/aesexe enc archivo.txt keyAES128.bin cifrado.aes
./output/aesexe dec cifrado.aes keyAES128.bin resultado.txt
./output/aesexe enc-192 archivo.txt keyAES192.bin cifrado.aes
./output/aesexe dec-192 cifrado.aes keyAES192.bin resultado.txt
./output/aesexe enc-256 archivo.txt keyaes256.bin cifrado.aes
./output/aesexe dec-256 cifrado.aes keyaes256.bin resultado.txt
./output/aesexe enc-cc20 archivo.txt keychacha20.bin cifrado.cc20
./output/aesexe dec-cc20 cifrado.cc20 keychacha20.bin resultado.txt
```

El formato conserva compatibilidad con la versión C++: completa el último
bloque con bytes cero. La salida descifrada puede contener ese padding final.

## Servidor web

```bash
./gen-certs.sh 127.0.0.1
./output/aesexe ser 127.0.0.1 8080
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
