AESExe – AES Encryption in C++
This project implements a simple file encryption tool using the AES-128 algorithm, written in pure C++.

How to Compile:

g++ AESmain.cpp -o aesExe

How to Use:

./aesExe file.txt
The program reads the input file in 16-byte blocks.

Each block is encrypted using AES-128.

The encrypted output is saved as a binary file: encrypt_archive.aes.

 Project Structure:
AESmain.cpp: Contains the main function and example usage.

Cipher.hpp / Cipher.cpp: Implementation of the AES cipher.

FileHandler: Class that manages file I/O in 16-byte blocks.

