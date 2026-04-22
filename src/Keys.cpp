
/*
    Con el fin de mantener la modularidad,
    se separan en dos archivos, se dejan por un lado los
    includes con las deniciones de clases
    y en src los .cpp con los metodos
*/
#include "../include/Keys.hpp"
#include <cstdint>
#include <vector>
#include <string>
#include <cstddef>
#include <stdexcept>
#include <random>
#include <fstream>
#include <iostream>

//constructor
Keys::Keys(std::string pathKey) {
    if(pathKey == "aes128") {
        keyAES128();
    } else if(pathKey == "aes192") {
        keyAES192();
    } else if(pathKey == "aes256") {
        keyAES256(pathKey);
    } else if(pathKey == "chacha20") {
        /*
            la generacion de las clave de cifrado
            de AES256 y ChaCha20 son las mismas,
            comparten la misma longitud de bits
        */
        keyAES256(pathKey);
    } else throw std::invalid_argument("Algoritmo de clave no soportado: \e[31m" + pathKey + "\e[0m");
}

/*
    generador de keys para AES128
    (16 bytes)
*/
inline void Keys::keyAES128() {
    std::vector<uint8_t> key(16);
    std::random_device rd;
    std::mt19937 gen(rd());//incrementa la entropia
    std::uniform_int_distribution<> dis(0, 255);

    for (auto &byte : key) {//generacion de los bytes de la key
        byte = static_cast<uint8_t>(dis(gen));
    }

    std::ofstream outFile("keyAES128.bin", std::ios::binary); //operacion sobre el archivo key.bin
    if (!outFile) {
        throw std::runtime_error("No se pudo abrir el archivo de clave");
    } else {//escritura de key.bin
        outFile.write(reinterpret_cast<const char*>(key.data()), key.size());
        outFile.close();
        std::cout << "[\e[32mAES128\e[0m]: Clave generada con exito..." << std::endl;
    }

}

/*
    generador de keys para AES192
    (24 bytes)
*/
inline void Keys::keyAES192() {
    std::vector<uint8_t> key(24);
    std::random_device rd;
    std::mt19937 gen(rd());//incrementa la entropia
    std::uniform_int_distribution<> dis(0, 255);

    for (auto &byte : key) {//generacion de los bytes de la key
        byte = static_cast<uint8_t>(dis(gen));
    }

    std::ofstream outFile("keyAES192.bin", std::ios::binary); //operacion sobre el archivo key.bin
    if (!outFile) {
        throw std::runtime_error("No se pudo abrir el archivo de clave");
    } else {//escritura de key.bin
        outFile.write(reinterpret_cast<const char*>(key.data()), key.size());
        outFile.close();
        std::cout << "[\e[32mAES192\e[0m]: Clave generada con exito..." << std::endl;
    }

}
/*
    generador de keys para AES256
    (32 bytes)
*/
inline void Keys::keyAES256(std::string typeAlgo) {
    std::vector<uint8_t> key(32);
    std::random_device rd;
    std::mt19937 gen(rd());//incrementa la entropia
    std::uniform_int_distribution<> dis(0, 255);

    for (auto &byte : key) {
        byte = static_cast<uint8_t>(dis(gen));
    }

    std::ofstream outFile("key"+ typeAlgo +".bin", std::ios::binary);
    if (!outFile) {
        throw std::runtime_error("No se pudo abrir el archivo de clave");
    } else {
        outFile.write(reinterpret_cast<const char*>(key.data()), key.size());
        outFile.close();
        
        if(typeAlgo=="aes256") std::cout << "[\e[32mAES256\e[0m]: Clave generada con exito..." << std::endl;
        else  std::cout << "[\e[32mCHCH20\e[0m]: Clave generada con exito..." << std::endl;
    }
}

