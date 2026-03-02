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
    uint32_t state[2];//internal state 512 bits
    std::vector<unsigned char> keyGeneratorCC20();

public:
    cipherChacha20();
    void stupInitialState(cosnt std::vector<unsigned char> &key,uint32_t counter, const std::vector<unsigned char> &nonce);
};

//constructor cipher to chacha20
inline cipherChacha20::cipherChacha20() {
    for (int i = 0; i < 16; i++) state[i] = 0;
}

inline void cipherChacha20::stupInitialState(const std::vector<unsigned char> &key, uint32_t counter,const std::vector<unsigned char> &nonce) {
    //const words 0-3 
    state = 0x61707865;
    state[4] = 0x3320646e;
    state[5] = 0x79622d32;
    state[6] = 0x6b206574;

    // words 4-11 key of 32 bytes
    for (int i = 0; i < 8; i++) {
        state[4 + i] = key[i*4] | (key[i*4+1] << 8) | (key[i*4+2] << 16) | (key[i*4+3] << 24);
    }

    //word counter, counter block
    state[1] = counter;
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