# Historial de Cambios (Changelog)

Todos los cambios notables en este proyecto serán documentados en este archivo.

El formato se basa en [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
y este proyecto se adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
## [Unreleased]
- Implementacion de AES256, AES192 y AES128 como clases hijas de una clase AES
## [0.0.3] - 2026-04-19
### Añadido
- Incorporacion de un archvo Makefile con ocpciones de debugeo `<make> <make debug> <make clean>`

## [0.0.2] - 2026-04-18

### Añadido
- Implemntacion de `chacha20` como algoritmo secundario a eleccion.
- Implementacion de `keys` para construccion de archivos key AES128, AES256 y chacha20
- La interfaz de linea de comandos incorpora `<enc-cc20/dec-cc20> <entrada> <clave> <salida>`.
- La interfas de linea de comandos incorpora para la creacion de keys `--key <aes128/aes256/chacha20>`.
### Cambiado
- Se modifico el main para permitir la gestion de keys y la implementacion de chacha20
- Se incorporo al .gitignore `*.cc20` para los archivos binarios de cc20
- Se implemento un manual `--help`.


## [0.0.1] - 2026-04-16

### Añadido
- Interfaz `ICipher` para la abstracción de algoritmos.
- Implementación `AES128` para cifrado y descifrado a nivel de bloque.
- `StreamProcessor` para el manejo escalable de E/S de archivos (procesamiento bloque por bloque).
- Nueva estructura de proyecto: `src/`, `include/`, `output/` y `wiki/`.
- Gitignore y gitkeep para la gestión del espacio de trabajo.
- Documentación Wiki con detalles de la arquitectura.

### Cambiado
- Refactorizado el `main` monolítico en componentes desacoplados.
- Movida la lógica de AES desde las clases legadas a una clase unificada `AES128`.
- Actualizada la interfaz de línea de comandos para usar `<enc/dec> <entrada> <clave> <salida>`.

### Eliminado
- Archivos legados: `Cipher.hpp`, `Decipher.hpp`, `colorString.hpp`, `chacha20.hpp`.
- Directorio de backup de Emacs.
- Salida directa por consola desde los algoritmos de cifrado.
