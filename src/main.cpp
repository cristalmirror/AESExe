#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "../include/AES128.hpp"
#include "../include/StreamProcessor.hpp"

std::vector<uint8_t> loadKey(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), {});
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Uso: " << argv[0] << " <enc/dec> <archivo> <clave> <salida>" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::ifstream inFile(argv[2], std::ios::binary);
    std::vector<uint8_t> key = loadKey(argv[3]);
    std::ofstream outFile(argv[4], std::ios::binary);

    if (!inFile || key.empty() || !outFile) {
        std::cerr << "Error al abrir archivos o clave invalida" << std::endl;
        return 1;
    }

    AES128 aes(key);
    
    if (mode == "enc") {
        StreamProcessor::process(aes, inFile, outFile, true);
    } else if (mode == "dec") {
        StreamProcessor::process(aes, inFile, outFile, false);
    } else {
        std::cerr << "Modo invalido: use 'enc' o 'dec'" << std::endl;
        return 1;
    }

    return 0;
}
