
#ifndef KEYS_HPP
#define KEYS_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <cstddef>
#include <stdexcept>
#include <random>
#include <fstream>
#include <iostream>

class Keys {
public:
    Keys(std::string pathKey);
private:
    void keyAES128();
    void keyAES192();
    void keyAES256(std::string typeAlgo);
};

#endif // KEYS_HPP