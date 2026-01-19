#ifndef DECIPHER_HPP
#define DECIPHER_HPP

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include "Cipher.hpp"
#include "colorString.hpp"
class AESDecipher {
public:
    static const unsigned char inv_sbox[256];
    AESDecipher(const std::vector<unsigned char> &key);
    std::vector<unsigned char> decryptBlock(const std::vector<unsigned char> &block);
    std::vector<std::vector<unsigned char>> generateRandomKey(const std::vector<unsigned char>& key);
private:
    std::vector<std::vector<unsigned char>> keys;
    void invSubBytes(std::vector<unsigned char> &state);
    void invShiftRows(std::vector<unsigned char> &state);
    void invMixColumns(std::vector<unsigned char> &state);
    unsigned char gmul(unsigned char a, unsigned char b);
    void addRoundKey(std::vector<unsigned char>& state,const std::vector<unsigned char>& key);
    // Multiplies a byte by 2 in the finite field GF(2^8)
    unsigned char xtime(unsigned char x);
};

const unsigned char AESDecipher::inv_sbox[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

static const unsigned char rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

AESDecipher::AESDecipher(const std::vector<unsigned char> &key) {
    this->keys = generateRandomKey(key);
}


inline std::vector<unsigned char> AESDecipher::decryptBlock(const std::vector<unsigned char> &block) {
    std::vector<unsigned char> state = block;
    int cont=10;
    std::cout <<Color::NARANJA_NEGRO <<"[ROUND]: "<< Color::RESET;
    addRoundKey(state, keys[10]);
    invShiftRows(state);
    invSubBytes(state);
    std::cout <<Color::NARANJA << cont << " ";
    cont--;
    for (int round = 9; round >= 1; round-- ) {
        addRoundKey(state, keys[round]);
        invMixColumns(state);
        invShiftRows(state);
        invSubBytes(state);        
        std::cout << cont << " ";
        cont--;
    }
    addRoundKey(state, keys[0]);
    std::cout << cont << " ";
    std::cout << Color::RESET <<std::endl;
    return state;
}

inline void AESDecipher::invSubBytes(std::vector<unsigned char> &state) {
    for (size_t i = 0; i < state.size(); i++) {
        state[i] = AESDecipher::inv_sbox[state[i]];
    }
}

inline void AESDecipher::invShiftRows(std::vector<unsigned char> &state) {
    std::vector<unsigned char> temp(16);
    //first file(without changes)
    temp[0]=state[0];
    temp[4]=state[4];
    temp[8]=state[8];
    temp[12]=state[12];
     //second file
    temp[1]=state[13];
    temp[5]=state[1];
    temp[9]=state[5];
    temp[13]=state[9];
    //third file
    temp[2]=state[10];
    temp[6]=state[14];
    temp[10]=state[2];
    temp[14]=state[6];
    //fourd file
    temp[3]=state[7];
    temp[7]=state[11];
    temp[11]=state[15];
    temp[15]=state[3];
    //copy the new state
    state = temp;
}
//GF(2^8) multiplications
inline unsigned char AESDecipher::gmul(unsigned char a, unsigned char b) {

    unsigned char p = 0;

    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        bool hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set) a ^=0x1b;
        b >>=1;
    }
    
    return p;
}

inline void AESDecipher::invMixColumns(std::vector<unsigned char> &state) {
    for (int c = 0; c < 4; c++) {
        unsigned char s0 = state[0 + 4 * c];
        unsigned char s1 = state[1 + 4 * c];
        unsigned char s2 = state[2 + 4 * c];
        unsigned char s3 = state[3 + 4 * c];

        state[0 + 4 * c] = gmul(s0, 0x0e) ^ gmul(s1, 0x0b) ^ gmul(s2, 0x0d) ^ gmul(s3, 0x09);
        state[1 + 4 * c] = gmul(s0, 0x09) ^ gmul(s1, 0x0e) ^ gmul(s2, 0x0b) ^ gmul(s3, 0x0d);
        state[2 + 4 * c] = gmul(s0, 0x0d) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0e) ^ gmul(s3, 0x0b);
        state[3 + 4 * c] = gmul(s0, 0x0b) ^ gmul(s1, 0x0d) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0e);
    }
}

inline void AESDecipher::addRoundKey(std::vector<unsigned char>& state,const std::vector<unsigned char>& key) {
    for (size_t i = 0; i < state.size(); i++) {
        state[i] ^= key[i];
    }
}
// Multiplies a byte by 2 in the finite field GF(2^8)
inline unsigned char AESDecipher::xtime(unsigned char x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1b :0x00);
}
//random keys generation for rounds
inline std::vector<std::vector<unsigned char>> AESDecipher::generateRandomKey(const std::vector<unsigned char>& key) {

    const int Nr = 10; //rounds
    
    std::cout<< Color::VERDE <<"<<[ MAKING EXTENDED KEYS ]>>"<< Color::RESET <<std::endl;    
    //expanded key
    std::vector<unsigned char> expanded(176);
    //copy all base keys in the first 4 words
    for (int i = 0; i < 16; i++) expanded[i] = key[i];
    int bytesGenerated = 16;
    unsigned char rcon = 0x01; //const initial round
    
    //expand keys
    while (bytesGenerated < 176) {
        //The previous word (roundKeys[i-1]) is copied as base (temp).
        std::vector<unsigned char> temp(4);
        for (int j = 0; j < 4; j++) {
            temp[j] = expanded[bytesGenerated - 4 + j];
        }

        if (bytesGenerated % 16 == 0) {
            std::rotate(temp.begin(), temp.begin() + 1, temp.end());

            //subWord
            for (int j = 0; j < 4; j++) {
                temp[j] = AESCipher::sbox[temp[j]];
            }
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
    //group keys in 11 vectors of 16 bytes
    std::vector<std::vector<unsigned char>> finalKeys(11, std::vector<unsigned char>(16));
    for (int i = 0; i < 11; i++) {
        for (int j = 0; j < 16; j++) {
            finalKeys[i][j] = expanded[i * 16 + j];
        }
    }   
    return finalKeys;
}
#endif
