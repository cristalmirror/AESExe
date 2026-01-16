AESExe – AES Encryption in C++ This project implements a simple file encryption tool using the AES-128 algorithm, written in pure C++.

How to Compile:

`g++ AESmain.cpp -o aesexe`

How to Use:

Encrypt exaple:

`./aesExe file.txt key.aes`

Decrypt example:

`./aesExe encrypted.aes key.aes resutl.txt`

Each block is encrypted using AES-128.

The encrypted output is saved as a binary file: encrypt_archive.aes.

Project Structure: AESmain.cpp: Contains the main function and example usage.

Cipher.hpp / Cipher.cpp: Implementation of the AES cipher.

FileHandler: Class that manages file I/O in 16-byte blocks.
