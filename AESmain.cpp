#include<iostream>
#include<fstream>
#include<vector>
#include<cstring>
#include<algorithm>
#include<iomanip>
#include"Cipher.hpp"
#include"Decipher.hpp"
#include"colorString.hpp"

using namespace std;

const int BLOCK_SIZE = 16;

/*class that craate the bocks*/
class FileHandler {
public:
    //mipulation of archive
    static vector<vector<unsigned char>> readFileInBlocks(const string &filename){
        ifstream inFile(filename, ios::binary);
        if (!inFile) {
            cerr<< Color::ROJO <<"Error in open archive"<< Color::RESET <<endl;
            return{};
        }

        //put the bits of archive in blocks vectors
        vector<vector<unsigned char>> blocks;
        vector<unsigned char> buffer(BLOCK_SIZE,0);
        while(inFile.read(reinterpret_cast<char*>(buffer.data()),BLOCK_SIZE)) {
            blocks.push_back(buffer);
        }

        //process last block if so small
        size_t bytesRead = inFile.gcount();
        if (bytesRead > 0) {
            vector<unsigned char> lastBlock(BLOCK_SIZE,0);
            for (size_t i = 0; i < bytesRead; i++) {
                lastBlock[i] = buffer[i];
            }
            blocks.push_back(lastBlock);
            /* last block procesing
            buffer.assign(BLOCK_SIZE,0); //push 0 if is necesary
            inFile.read(reinterpret_cast<char*>(buffer.data()),bytesRead);
            blocks.push_back(buffer);
            */
        }
        inFile.close();
        return blocks;
    }
    static void writeBlocksToFile(const string& filename, const vector<vector<unsigned char>>& blocks);
    
    
};
//write blocks in binary file
void FileHandler::writeBlocksToFile(const string& filename, const vector<vector<unsigned char>>& blocks) {
    ofstream outFile(filename,ios::binary);
    int cont = 0;
    if (!outFile) {
        cerr<< Color::ROJO <<"Error open file to write"<< Color::RESET <<endl;
        return;
    }
    cout <<Color::MAGENTA<<"*<<[writing binary bloks]>>*"<< Color::RESET<<endl;
    for (const auto& block: blocks) {
        outFile.write(reinterpret_cast<const char*>(block.data()), block.size());
    }
    
    outFile.close();
    cout << Color::NARANJA <<"*** Blocks => ["<< blocks.size() <<"] write in: "<< filename <<"***"<< Color::RESET<<endl;
}

//ends file determinations
bool endsWith(const string& str, const string& suffix) {
    return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}
//readfile of key.aes
vector<unsigned char> loadKeyFromFile(const string& filename) {
    ifstream keyFile(filename, ios::binary);
    vector<unsigned char> key(16);
    if (!keyFile.read(reinterpret_cast<char*>(key.data()), 16)) {
        throw runtime_error("Error al leer la clave desde el archivo: " + filename);
    }

    cout <<Color::VERDE <<"Clave cargada desde el archivo (hexadecimal): ";
    for (unsigned char byte : key) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte) << " ";
    }
    cout << dec << Color::RESET <<endl;
    
    return key;
}

void printBlock(const vector<unsigned char>& block, const string& label) {
    cout << label << ": ";
    for (unsigned char byte : block) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte) << " ";
    }
    cout << dec <<Color::RESET<< endl;
}

//delete prints in console
void deletePrintsLine(int cantidad) {
    for (int i = 0; i < cantidad; ++i) {
        // \33[A  -> move cursor up one line
        // \33[2K -> delete entire line
        // \r     -> move cursor to the beginning of the line
        std::cout << "\33[A\33[2K\r" << std::flush;
    }
}
//function main 
int main(int argc,char *argv[]) {
#ifdef _WIN32
    initTerminalColors();
#endif
    if (argc < 2) {
        cerr<< Color::ROJO <<"Uso: "<< argv[0] << "<nombre_de_archivo.txt>"<< Color::RESET <<endl;
        return 1;
    }

    string filename = argv[1]; 
    vector<vector<unsigned char>> blocks =FileHandler::readFileInBlocks(filename);
    cout<< Color::AMARILLO <<"se leyeron "<< blocks.size() << " bloques de "<< BLOCK_SIZE <<"bytes." << Color::RESET <<endl;
    //manual of user
    if(filename == "-m" || filename =="--manual" || filename == "-h"|| filename =="--help") {
        deletePrintsLine(2);
        cout << Color::NARANJA << "==========================================================" << Color::RESET << endl;
        cout << Color::NARANJA << "          USER MANUAL - AES-128 TOOL AESEXE V1.1          " << Color::RESET << endl;
        cout << Color::NARANJA << "==========================================================" << Color::RESET << endl;

        cout << endl << Color::AZUL_FONDO<< " DESCRIPTION: " << Color::RESET << endl;
        cout << " This tool allows you to encrypt files " << endl;
        cout << " and decrypt binary files (.aes) using the industry " << endl;
        cout << " standard AES-128 block cipher algorithm." << endl;

        cout << endl << Color::AZUL_FONDO << " USAGE MODES EXAMPLE: " << Color::RESET << endl;
    
        cout << endl << Color::VERDE << " 1. ENCRYPT:" << Color::RESET << endl;
        cout << "    Command: " << argv[0] << " <input.txt> <output.aes>" << endl;
        cout << "    Note: A random key will be generated in 'key.aes' automatically." << endl;

        cout << endl << Color::VERDE << " 2. DECRYPT:" << Color::RESET << endl;
        cout << "    Command: " << argv[0] << " <input.aes> <key.aes> <output.txt>" << endl;
        cout << "    Note: Requires the specific key file generated during encryption." << endl;

        cout << endl << Color::AZUL_FONDO << " TECHNICAL DETAILS: " << Color::RESET << endl;
        cout << " - Cipher Block Size: " << Color::NARANJA << "128 bits (16 bytes)" << Color::RESET << endl;
        cout << " - Cipher Rounds:     " << Color::NARANJA << "10 rounds" << Color::RESET << endl;
        cout << " - Support:           " << Color::NARANJA << "Cross-platform (Linux / Windows)" << Color::RESET << endl;

        cout << endl << Color::NARANJA << "==========================================================" << Color::RESET << endl;
        cout << " Developed in Argentina - 2026 for: https://github.com/cristalmirror" << endl;
        goto fin_prog;
    } else if (!endsWith(filename,".aes")) {
        string filenameOutput = argv[2];
        vector<unsigned char> key = generateSaveKeyBase("key.aes");
        AESCipher cipher(key);
        vector<vector<unsigned char>> encryptedBlocks;
        //cipher and write blocks
        for (size_t i = 0; i < blocks.size(); i++) {
            vector<unsigned char> encrypted = cipher.encryptBlock(blocks[i]);
            printBlock(blocks[i], Color::NARANJA_NEGRO + "Bloque original " + to_string(i));
            printBlock(encrypted, Color::AZUL_FONDO + "Bloque cifrado " + to_string(i));
            encryptedBlocks.push_back(encrypted);
            cout<< Color::CIAN << "***block "<< i <<"/"<<blocks.size()<<" encrypted ***"<< Color::RESET <<endl;
        
        }

        FileHandler::writeBlocksToFile(filenameOutput, encryptedBlocks);
    } else if (endsWith(filename,".aes")) {
            
        //decipher
        string keyFilename = argv[2];
        string filenameOutputDecrpyt = argv[3];
        vector<unsigned char> key = loadKeyFromFile(keyFilename);
        AESDecipher decipher(key);
            
        vector<vector<unsigned char>> decryptedBlocks;
        for (size_t i = 0; i < blocks.size(); i++) {
            vector<unsigned char> decrypted = decipher.decryptBlock(blocks[i]);
            printBlock(blocks[i], Color::AZUL_FONDO + "Bloque cifrado " + std::to_string(i));
            printBlock(decrypted,  Color::NARANJA_NEGRO + "Bloque descifrado " + std::to_string(i));
            decryptedBlocks.push_back(decrypted);
            cout << Color::CIAN << "*** Bloque " << i + 1 << "/" << blocks.size() << " descifrado ***" << Color::RESET <<endl;
        }
        FileHandler::writeBlocksToFile(filenameOutputDecrpyt, decryptedBlocks);

    } else {
        cerr << Color::ROJO << "Extension de archivo no reconocida. Use .txt para cifrar o .aes para descifrar." << Color::RESET <<endl;
        return 1;
    }
    fin_prog:
    return 0;
}
