#include "../include/loadKey.hpp"

std::vector<uint8_t> loadKey(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::cout << "[\e[32mAESExe\e[0m]: Clave cargada con exito..." << std::endl;
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), {});
    
}
