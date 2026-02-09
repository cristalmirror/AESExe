#include <iostream>
#include <vector>
#include <algorithm>
#include <random>
//class that content the chacha20 cipher algorithm
class cipherChacha20 {
private:
    
    std::vector<unsigned char> keyGeneratorCC20();
public:
    cipherChacha20(std::vector<unsigned char> &key);
};

//constructor cipher to chacha20
inline cipherChacha20::cipherChacha20(std::vector<unsigned char> &key) {

}
inline std::vector<unsigned char> cipherChacha20::keyGeneratorCC20(){
    std::vector randomKey(32);//init vector
    std::random_device rd;
    std::mt19937 gen(rd()); //pseudo-random generator numbers
    std::uniform_int_distribution<>dis(0,255); //distribution

    //load the vector with aleatory numbers
    for (i = 0, i < 32, i++) {
        randomKey[i] = static_cast<unsigned char>(dis(gen));
    }
    std::cout << Color::AMARILLO <<"[CC20 TYPE]: *** base key has generated ***"<< Color::RESET <<std::endl;

    //generation file of key base

    for (unsigned char byte : randomKey) {
        std::cout << Color::CIAN << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << Color::RESET <<" ";
    }
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
//class that content the chacha20 decipher algorithm
class decipherChacha20 {
private:

public:
    decipherChacha20(std::vector<unsigned char> &key);
};

//constructor decipher to chacha20
inline decipherChacha20::decipherChacha20(std::vector<unsigned char> &key) {

}