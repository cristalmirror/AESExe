#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "../include/AES128.hpp"
#include "../include/chacha20.hpp"
#include "../include/StreamProcessor.hpp"
#include "../include/Keys.hpp"

//comandos y descripciones
struct Command {
    std::string usage;        // cómo se escribe
    std::string description;  // qué hace
};

//strings del manual
const std::vector<Command> COMMANDS = {
    {" --key <aes128/aes256/chacha20>","Genera una clave aleatoria en key.bin"},
    {" --help",                        "Muestra este manual"},
    {" enc <archivo> <clave> <salida>", "Cifra un archivo"},
    {" dec <archivo> <clave> <salida>", "Descifra un archivo"},
    {" enc-cc20 <archivo> <clave> <salida>", "Cifra un archivo chacha20"},
    {" dec-cc20 <archivo> <clave> <salida>", "Descifra un archivo chacha20"},
    
};

//cargador de las keys
std::vector<uint8_t> loadKey(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::cout << "[AESExe]: Clave cargada con exito..." << std::endl;
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), {});
    
}

//manual de uso
inline void help(std::string name) {
    std::cout << "=== AES/ChaCha20 - Manual de uso ===" << std::endl;
    std::cout << std::endl;
    for (const auto& cmd : COMMANDS) {
        std::cout << "  " << name << cmd.usage;
        std::cout << "      " << cmd.description << std::endl;
    }
}

int main(int argc, char* argv[]) {
    /*
        condicion de la generacion de
        keys para los algoritmos de cifrado
    */
    if (argc == 3 || argc == 2) {
        if (std::string(argv[1]) == "--help") {
            help(argv[0]);
            return 0;
        } else if (std::string(argv[1]) == "--key") {//generacion  de la key
            //construye la key segun algoritmo que se va usar
            Keys genkey(argv[2]);
        } else {
            std::cerr << "Uso: " << argv[0] << "con argumentos invalidos" << std::endl
               << "Use --help para obtener ayuda y ver las opciones disponibles." << std::endl;
               return 1;
        }

        return 0;
    }

    /*
        salida por falta de argumentos
        o exeso de los mismmos
    */
    if (argc < 5 || argc > 5) {
         std::cerr << "Uso: " << argv[0] << "con argumentos invalidos" <<std::endl << std::endl;
        help(argv[0]);
        return 1;
    }

    //variables y datos
    std::string mode = argv[1];
    std::ifstream inFile(argv[2], std::ios::binary);
    std::vector<uint8_t> key = loadKey(argv[3]);
    std::ofstream outFile(argv[4], std::ios::binary);

    /*
        manejador de archivos
    */
    if (!inFile || key.empty() || !outFile) {
        std::cerr << "Error al abrir archivos o clave invalida" << std::endl;
        return 1;
    }

    /*
        selector de modos
    */
    if (mode == "enc") {
        AES128 aes(key);
        StreamProcessor::process(aes, inFile, outFile, true);
        std::cout << "[AESExe]: *128 bits modo de cifrado AES*" << std::endl;
    } else if (mode == "dec") {
        AES128 aes(key);
        StreamProcessor::process(aes, inFile, outFile, false);
        std::cout << "[AESExe]: *128 bits modo de descifrado AES*" << std::endl;

    } else if(mode == "enc-cc20" || mode == "dec-cc20") {
        ChaCha20 cc20(key);
        StreamProcessor::process(cc20, inFile, outFile, true);
        std::cout << "[AESExe]: *256 bits modo de cifrado ChaCha20*" << std::endl;
    } else {
        std::cerr << "Uso: " << argv[0] << "con argumentos invalidos" << std::endl
           << "Use --help para obtener ayuda y ver las opciones disponibles." << std::endl;
           return 1;
    }

    return 0;
}
