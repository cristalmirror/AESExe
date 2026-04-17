# AESExe – Cifrado AES en C++

Este proyecto implementa una herramienta de cifrado de archivos utilizando el algoritmo AES-128, escrita en C++ puro con una arquitectura escalable y desacoplada.

## Arquitectura

La aplicación sigue principios de diseño SOLID, separando la lógica matemática del procesamiento de datos y la interfaz de usuario.

### Componentes Principales

- **ICipher**: Interfaz pura que define el contrato para cualquier algoritmo de cifrado. Permite intercambiar AES por otros algoritmos (como ChaCha20) sin modificar el sistema.
- **AES128**: Implementación concreta del algoritmo AES de 128 bits. Contiene la lógica de expansión de claves, S-Boxes y transformaciones de bloques. Es "pura lógica", sin dependencias de entrada/salida.
- **StreamProcessor**: Motor de procesamiento que maneja el flujo de datos. Lee archivos bloque a bloque, permitiendo procesar archivos de cualquier tamaño con un consumo de memoria mínimo y constante.
- **Main**: Orquestador que gestiona los argumentos de la línea de comandos y conecta los componentes.

## Estructura del Proyecto

- `include/`: Definiciones de interfaces y headers de los componentes.
- `src/`: Implementación del punto de entrada de la aplicación.
- `output/`: Directorio destinado a los binarios compilados y resultados.
- `CHANGELOG.md`: Historial detallado de versiones.

## Cómo Compilar

Para compilar el proyecto en sistemas Linux/Unix:

```bash
g++ src/main.cpp -Iinclude -o output/aesexe
```

## Cómo Usar

### Cifrar:

```bash
./output/aesexe enc archivo.txt clave.bin cifrado.aes
```

### Descifrar:

```bash
./output/aesexe dec cifrado.aes clave.bin resultado.txt
```

## Flujo de Datos

1. El usuario ejecuta el comando especificando modo (enc/dec), archivo, clave y salida.
2. `Main` carga la clave en memoria e inicializa `AES128`.
3. `StreamProcessor` abre los flujos de lectura y escritura.
4. Se procesa el archivo bloque a bloque (16 bytes) aplicando la transformación correspondiente.
5. El resultado se escribe directamente en el archivo de salida.
