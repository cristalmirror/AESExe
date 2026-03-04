#include <iostream>
#include <vector>
#include <algorithm>
#include <random>
#include <iomanip>
#include <fstream>
#include <cstdint>

//class that content the chacha20 cipher algorithm
class cipherChacha20 {
private:
    uint32_t state[16];//internal state 512 bits
    std::vector<unsigned char> keyGeneratorCC20();
    uint32_t ROTL(uint32_t v, int c);
public:
    cipherChacha20();
    void stupInitialState(cosnt std::vector<unsigned char> &key,uint32_t counter, const std::vector<unsigned char> &nonce);
    void encryptInCC20(std::vector<uint32_t> &plaintext);
};



//constructor cipher to chacha20
inline cipherChacha20::cipherChacha20() {
    for (int i = 0; i < 16; i++) state[i] = 0;
}

inline void cipherChacha20::encryptInCC20(std::vector<uint8_t> block) {
    uint32_t workingState[16];
    uint32_t initialState[16];

    for(int i = 0; i < 16; i++) initialState[i] = workingStste[i] = state[i];

    for(int i = 0; i < 10; i++) {
      // Rondas de Columnas
        quarterRound(workingState[0], workingState[4], workingState[8],  workingState[12]);
        quarterRound(workingState[1], workingState[5], workingState[9],  workingState[13]);
        quarterRound(workingState[2], workingState[6], workingState[10], workingState[14]);
        quarterRound(workingState[3], workingState[7], workingState[11], workingState[15]);
        
        // Rondas Diagonales
        quarterRound(workingState[0], workingState[5], workingState[10], workingState[15]);
        quarterRound(workingState[1], workingState[6], workingState[11], workingState[12]);
        quarterRound(workingState[2], workingState[7], workingState[8],  workingState[13]);
        quarterRound(workingState[3], workingState[4], workingState[9],  workingState[14]);
    
    }
     for (int i = 0; i < 16; i++) {
        workingState[i] += initialState[i];
    }
    // 4. XOR: Aplicar el flujo de clave (Key Stream) al texto plano
    for (size_t i = 0; i < block.size() && i < 64; i++) {
        // Extraer bytes de las palabras de 32 bits (Little-Endian)
        block[i] ^= (workingState[i / 4] >> (8 * (i % 4))) & 0xFF;
    }
    state[12]++;
}

//Rotation of bits to left for words of 32 bits
inline uint32_t cipherChacha20::ROTL(uint32_t v, int c) {
    return (v << c) | (v >> (32 - c));
}

inline void cipherChacha20::quarterRound(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    a += b; d ^= a; d = ROTL(d, 16);
    c += d; b ^= c; b = ROTL(b, 12);
    a += b; b ^= a; d = ROTL(d, 8);
    c += d; b ^= c; b = ROTL(b, 7);
}

inline void cipherChacha20::stupInitialState(const std::vector<unsigned char> &key, uint32_t counter,const std::vector<unsigned char> &nonce) {
    //const words 0-3 
    state[0]= 0x61707865;
    state[1] = 0x3320646e; 
    state[2] = 0x79622d32; 
    state[3] = 0x6b206574;

    // words 4-11 key of 32 bytes
    for (int i = 0; i < 8; i++) {
        state[4 + i] = key[i*4] | (key[i*4+1] << 8) | (key[i*4+2] << 16) | (key[i*4+3] << 24);
    }

    //word counter, counter block
    state[12] = counter;

    //words of the nonce
    for (int i = 0; i < 3; i++){
        state[13 + i] = nonce[i*4] | (nonce[i*4+1] << 8) | (nonce[i*4+2] << 16) | (nonce[i*4+3] << 24);
    }


}

inline std::vector<unsigned char> cipherChacha20::keyGeneratorCC20(){
    std::vector<unsigned char> randomKey(32);//init vector
    std::random_device rd;
    std::mt19937 gen(rd()); //pseudo-random generator numbers
    std::uniform_int_distribution<>dis(0,255); //distribution

    //load the vector with aleatory numbers
    for (i = 0; i < 32; i++) {
        randomKey[i] = static_cast<unsigned char>(dis(gen));
    }
    std::cout << Color::AMARILLO <<"[CC20 TYPE]: *** base key has generated ***"<< Color::RESET <<std::endl;

    //generation file of key base

    for (unsigned char byte : randomKey) {
        std::cout << Color::CIAN << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << Color::RESET <<" ";
    }
    //write binary archive
    std::ofstream outFile(filename, std::ios::binary);
    if (!outFile) {
        std::cerr<< Color::ROJO <<"[CC20 TYPE]: Error writing key to file"<< Color::RESET <<std::endl;
        return {};
    } else {
        outFile.write(reinterpret_cast<const char*>(randomKey.data()),randomKey.size());
        outFile.close();
        std::cout<< Color::VERDE <<"[CC20 TYPE]: -> [base key has writed]"<< Color::RESET <<std::endl;
        return randomKey;
    }
}


/*
    part of the code in the last class is a adapatation
    of code in Cipher.hpp and Decipher.hpp...

    class that content the chacha20 decipher algorithm
*/
class decipherChacha20 {
private:

public:
    decipherChacha20(std::vector<unsigned char> &key);
};

//constructor decipher to chacha20
inline decipherChacha20::decipherChacha20(std::vector<unsigned char> &key) {

}