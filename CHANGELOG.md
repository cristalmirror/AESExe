# Historial de Cambios (Changelog)

Todos los cambios notables en este proyecto serán documentados en este archivo.

El formato se basa en [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
y este proyecto se adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
## [Unreleased]

## [0.4.0] 2026-08-28
### Cambiado
- El backend completo fue migrado de C++17 a Rust 2024.
- El servidor ahora valida claves, limita peticiones y usa el mismo origen del cliente web.

### Eliminado
- Código fuente, headers y dependencias de compilación C++.

## [0.3.2] 2026-06-15
### Corregido
- `handleStaticFile`: el path raíz estaba definido como `"../"` en lugar de `"/"`, por lo que el browser nunca recibía el HTML al hacer `GET /`.
- `handleStaticFile`: el body del response estaba hardcodeado al literal `"File not Found"` en lugar de `buf.str()`, descartando el contenido leído del archivo.

## [0.3.1] 2026-06-15
### Añadido
- Se implementó `handleStaticFile` en `Server` para servir los archivos estáticos del cliente web (`GET /`, `GET /src/main.js`, `GET /style/style.css`).
- Se agregó ruta `GET` en el router de `connectManager` que delega a `handleStaticFile`.

### Corregido
- `connectManager`: se agregó lectura en dos fases (Phase 1: headers, Phase 2: body por `Content-Length`) para evitar truncado de peticiones POST con body grande.
- `connectManager`: se agregó lambda `closeConnection` y se corrigieron fugas de recursos (`close(SSL_get_fd(ssl))` faltante en múltiples rutas de error).
- `handleEncrypt`: se agregó validación del campo `algo` antes de generar la clave; sin esto `Keys::generate` devolvía 16 bytes por defecto y el archivo cifrado quedaba vacío.
- `initServer`: se corrigió `bind()` fallido con `return` reemplazado por `exit(EXIT_FAILURE)`; se agregó chequeo de error en `socket()`.
- `main.cpp`: se corrigió el chequeo de `argc` para permitir el modo `ser` con 4 argumentos y se evita validar archivos cuando el modo es `ser`.
- Cliente (`main.js`): se corrigió `getMode()` — los radio buttons tenían `name` distintos y podían quedar ambos seleccionados.
- Cliente (`main.js`): `encrypt()` y `decrypt()` no enviaban el campo `algo` al servidor, causando respuesta 400.
- Cliente (`main.js`): `decrypt()` intentaba parsear la respuesta como JSON (`res.json()`); el servidor devuelve texto plano (`res.text()`).
- Cliente (`main.js`): URL del servidor corregida de `localhost` a `192.168.1.35:8080`.
- Cliente (`index.html`): radio buttons unificados con `name="mode"` y se agregó selector de algoritmo `<select id="algo">`.
- Certificado TLS regenerado con `CN=192.168.1.35` (anterior era `192.168.0.251`).

## [0.3.0] 2026-06-8
### Añadido
- Se crearon los archivos `StreamProcessorGCM.hpp` y `StreamProcessorGCM.cpp` con una nueva clase `StreamProcessorGCM` que implementa el modo de cifrado autenticado GCM (NIST SP 800-38D), incluyendo multiplicación en GF(2¹²⁸), GHASH, modo contador GCTR, y formato de salida `[nonce 12 B][ciphertext][tag 16 B]`.
- Se añadió el método estático `Keys::generate(const std::string& algo)` en `Keys.hpp` y `Keys.cpp` que genera una clave aleatoria segura mediante `RAND_bytes` de OpenSSL según el algoritmo indicado (16 B para AES-128, 24 B para AES-192, 32 B para AES-256 y ChaCha20).
- Se implementaron en `Server` los métodos `handleEncrypt`, `handleDecrypt` y `handleOpertions` para gestionar las rutas `POST /encrypt`, `POST /decrypt` y preflight CORS `OPTIONS`.
- Se añadieron los helpers HTTP en `Server`: `parseHttpPath`, `parseHttpBody`, `base64Encode`, `base64Decode`, `sendResponse` y `sendBinaryRespose`.
- Se agregó la función auxiliar `validCuil` para validar el CUIL recibido en las peticiones.
- Se incorporaron headers CORS globales (`Access-Control-Allow-Origin`, `Allow-Methods`, `Allow-Headers`) a todas las respuestas del servidor.

### Modificado
- Se reemplazó el método `operationsMannager` en `Server` por un enrutador HTTP que despacha según método y ruta.
- Se refactorizó `connectManager` en `Server.cpp`: la respuesta HTTP hardcodeada fue sustituida por el enrutador; se corrigió el manejo del error de handshake SSL agregando `SSL_free` y retorno temprano.
- Se marcaron `AES::sbox` y `AES::invSbox` en `AES.hpp` como `inline` para evitar errores de definición múltiple al incluirse en varios translation units.
- Se actualizó `Makefile` para incluir `src/loadKey.cpp` y `src/StreamProcessorGCM.cpp` en la compilación.

### Pendiente / Comentado
- La reconstrucción de la clave desde `raw_key` en `handleDecrypt` está comentada (`Keys key(algo, raw_key)`) a la espera de implementar ese constructor en la clase `loadKey`.

## [0.2.6] 2026-06-7
### Añadido
- Se implemento un grupo de metodos para la clase server que implemntan el uso de base64 en la gestion de keys.
### Modifico
- Se modifico la clase Server 
### Eliminado
- Se elmino el metodo opertionsMannager

## [0.2.5] 2026-06-6                                                                                                                                                    
### Añadido
- Se creo el plugin de descarga para le la key desde el navegador.

## [0.2.4] 2026-06-5                                                                                                                                                    
### Añadido
- Se añadio la logica del cliente en main.js
## [0.2.3] 2026-05-31
### Añadido
-Se creo el metodo `operationsMannager()` para gestionar los algoritmos.

## [0.2.2] 2026-05-25
### Añadido
-Se creo la estructura basica del cliente.
## [0.2.1] 2026-05-24
### Añadido
- Se añadieron las operaciones que fueron necesarias dentro del servidor

## [0.2.0] 2026-05-22
### Añadido
- Se implemento las archivos `Server.hpp` y `Server.cpp` para crear opciones de sifrado en red local.

## [0.1.0] 2026-04-21
### Añadido
- Implementacion de AES256, AES192 y AES128 como clases hijas de una clase AES
- Se modifico el main para la implementacion de AES192
- Se añadio la clase abstracta AES que es padre de todas las clases AES con su logica 
### Cambiado
- La interfas de linea de comandos incorpora para la creacion de keys para AES192 `--key aes192`.

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
