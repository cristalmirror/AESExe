#ifndef CIPHER_HPP
#define CIPHER_HPP

#include <vector>
#include <random>
#include <algorithm>
#include <iomanip>
#include "colorString.hpp"
//Cipher class
class AESCipher {
public:
    static const unsigned char sbox[256];
    //constructor
    AESCipher(const std::vector<unsigned char> &key);
    //runing the parts of AES algoritm
    std::vector<unsigned char> encryptBlock(const std::vector<unsigned char> &block);
    //make keys
    std::vector<std::vector<unsigned char>> generateRandomKey(const std::vector<unsigned char> &key);
    
private:

    std::vector<std::vector<unsigned char>> keys;
    void subBytes(std::vector<unsigned char> &state);
    //method shitRows od AES
    void shiftRows(std::vector<unsigned char> &state);
    // Multiplies a byte by 2 in the finite field GF(2^8)
    unsigned char xtime(unsigned char x);
    //mixColumns method
    void mixColumns(std::vector<unsigned char> &state);
    //addRoundKey 
    void addRoundKey(std::vector<unsigned char> &state,const std::vector<unsigned char> &key);
    
};

const unsigned char AESCipher::sbox[256] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
        0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
        0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
        0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
        0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
        0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
        0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
        0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
        0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
        0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
        0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
        0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
        0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
        0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};
inline AESCipher::AESCipher(const std::vector<unsigned char> &key) {
    this->keys = generateRandomKey(key);
}

 //runing the parts of AES algoritm
inline std::vector<unsigned char> AESCipher::encryptBlock(const std::vector<unsigned char> &block) {
    std::vector<unsigned char> state = block;
    int cont=0;
    std::cout <<Color::NARANJA_NEGRO <<"[ROUND]: " << Color::RESET;
    addRoundKey(state,keys[0]); //initial round
    for (int round = 1; round <= 9; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, keys[round]);//expanded key for round
        std::cout<<Color::NARANJA<< cont << " ";
        cont++;
    }

    //last round without mixColumns 
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, keys[10]);
    std::cout << cont << " ";
    std::cout << Color::RESET <<std::endl;
    return state;
}

inline void AESCipher::subBytes(std::vector<unsigned char> &state) {
        
    for (size_t i = 0; i < state.size(); i++) {
        state[i] = AESCipher::sbox[state[i]];
    }
}

//method shitRows od AES
inline void AESCipher::shiftRows(std::vector<unsigned char> &state) {
    std::vector<unsigned char> temp(16);
    
    //first file(without changes)
    temp[0] = state[0];
    temp[4] = state[4];
    temp[8] = state[8];
    temp[12] = state[12];
    //second file
    temp[1] = state[5];
    temp[5] = state[9];
    temp[9] = state[13];
    temp[13] = state[1];
    //third file
    temp[2] = state[10];
    temp[6] = state[14];
    temp[10] = state[2];
    temp[14] = state[6];
    //fourd file
    temp[3] = state[15];
    temp[7] = state[3];
    temp[11] = state[7];
    temp[15] = state[11];
    
    //copy the new state
    state = temp;
}
// Multiplies a byte by 2 in the finite field GF(2^8)
inline unsigned char AESCipher::xtime(unsigned char x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1b :0x00);
}

inline void AESCipher::mixColumns(std::vector<unsigned char>& state) {
    for (int c=0; c < 4; c++) {
        int col = c * 4;
        unsigned char s0 = state[col+ 0];
        unsigned char s1 = state[col+ 1];
        unsigned char s2 = state[col+ 2];
        unsigned char s3 = state[col+ 3];

        state[col + 0] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
        state[col + 1] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
        state[col + 2] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
        state[col + 3] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);
    }
}

inline void AESCipher::addRoundKey(std::vector<unsigned char>& state,const std::vector<unsigned char>& key) {
    for (size_t i = 0; i < state.size(); i++) {
        state[i] ^= key[i];
    }
}
//random keys generation for rounds
inline std::vector<std::vector<unsigned char>> AESCipher::generateRandomKey(const std::vector<unsigned char>& key) {
    const int Nr = 10; //rounds
    
    std::cout << Color::VERDE <<"<<[ MAKING EXTENDED KEYS ]>>"<< Color::RESET <<std::endl;    
    //expanded key to 44 words(4 bytes each)
    std::vector<unsigned char> expanded(176);
    
    //copy all base keys in the first 4 words
    for (int i = 0; i < 16; i++) expanded[i] = key[i];
    int bytesGenerated = 16;
    unsigned char rcon = 0x01; //const initial round
    
    //The rest of the round keys begin to be generated (from i = 4 to i = 43).
    while (bytesGenerated < 176) {
        //The previous word (roundKeys[i-1]) is copied as base (temp).
        std::vector<unsigned char> temp(4);
        for (int i = 0; i < 4; i++) temp[i] = expanded[bytesGenerated - 4 + i];

        if (bytesGenerated % 16 == 0) {
            std::rotate(temp.begin(), temp.begin() + 1, temp.end());

            //subWord
            for (int j = 0; j < 4; j++) temp[j] = AESCipher::sbox[temp[j]];
            //XOR with rcon
            temp[0] ^= rcon;
            //update rcon
            rcon = xtime(rcon);
        }
        
        for (int j = 0; j < 4; j++) {
            expanded[bytesGenerated] = expanded[bytesGenerated - 16] ^ temp[j];
            bytesGenerated++;
        }
    }

    //Here we organize the expanded key into 11 round keys of 16 bytes each
    std::vector<std::vector<unsigned char>> finalKeys(11, std::vector<unsigned char>(16));
    for (int i = 0; i < 11; i++) {
        for (int j = 0; j < 16; j++) {
            finalKeys[i][j] = expanded[i * 16 + j];
        }
    }
    
    return finalKeys; 
}
//base key necesary to init the encryptation
inline std::vector<unsigned char> generateSaveKeyBase(const std::string &filename) {
    std::vector<unsigned char> randomKey(16);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0,255);

    for (auto &byte : randomKey) {
        byte = static_cast<unsigned char>(dis(gen));
    }
    std::cout << Color::AMARILLO <<"*** base key has generated ***"<< Color::RESET <<std::endl;
    //generation file of key base

    for (unsigned char byte : randomKey) {
        std::cout << Color::CIAN << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << Color::RESET <<" ";
    }
    std::ofstream outFile(filename, std::ios::binary);
    if (!outFile) {
        std::cerr<< Color::ROJO <<"Error writing key to file"<< Color::RESET <<std::endl;
        return {};
    } else {
        outFile.write(reinterpret_cast<const char*>(randomKey.data()),randomKey.size());
        outFile.close();
        std::cout<< Color::VERDE <<"-> [base key has writed]"<< Color::RESET <<std::endl;
        return randomKey;
    }
}
#endif
