#include<iostream>
#include<fstream>
#include<vector>
#include<cstring>
#include<algorithm>
#include <iomanip>
#include"Cipher.hpp"
#include"Decipher.hpp"

using namespace std;

const int BLOCK_SIZE = 16;

/*class that craate the bocks*/
class FileHandler {
public:
    //mipulation of archive
    static vector<vector<unsigned char>> readFileInBlocks(const string &filename){
        ifstream inFile(filename, ios::binary);
        if (!inFile) {
            cerr<<"Error in open archive"<<endl;
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
            buffer.assign(BLOCK_SIZE,0); //push 0 if is necesary
            inFile.read(reinterpret_cast<char*>(buffer.data()),bytesRead);
            blocks.push_back(buffer);
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
        cerr<<"Error open file to write"<<endl;
        return;
    }
    cout <<"*<<[writing binary bloks]>>*"<<endl;
    for (const auto& block: blocks) {
        outFile.write(reinterpret_cast<const char*>(block.data()), block.size());
    }
    
    outFile.close();
    cout <<"*** Blocks => ["<< blocks.size() <<"] write in: "<< filename <<"***"<<endl;
}

//ends file determinations
bool endsWith(const string& str, const string& suffix) {
    return str.size() >= suffix.size() &&
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}
//readfile of key.aes
vector<unsigned char> loadKeyFromFile(const string& filename) {
    ifstream keyFile(filename, ios::binary);
    vector<unsigned char> key(16);
    if (!keyFile.read(reinterpret_cast<char*>(key.data()), 16)) {
        throw runtime_error("Error al leer la clave desde el archivo: " + filename);
    }

    cout << "Clave cargada desde el archivo (hexadecimal): ";
    for (unsigned char byte : key) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte) << " ";
    }
    cout << dec << endl;
    
    return key;
}

void printBlock(const vector<unsigned char>& block, const string& label) {
    cout << label << ": ";
    for (unsigned char byte : block) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte) << " ";
    }
    cout << dec << endl;
}

//function main 
int main(int argc,char *argv[]) {
    
    if (argc < 2) {
        cerr <<"Uso: "<< argv[0] << "<nombre_de_archivo.txt>"<< endl;
        return 1;
    }
    
    string filename = argv[1];
    string filenameOutput = argv[2];
    vector<vector<unsigned char>> blocks =FileHandler::readFileInBlocks(filename);
    cout <<"se leyeron "<< blocks.size() << " bloques de "<< BLOCK_SIZE <<"bytes." << endl;

    //Key AES of 16 bytes
    if (endsWith(filename,".txt")) {
        vector<unsigned char> key = generateSaveKeyBase("key.aes");
        AESCipher cipher(key);
        vector<vector<unsigned char>> encryptedBlocks;
        //cipher and write blocks
        for (size_t i = 0; i < blocks.size(); i++) {
            vector<unsigned char> encrypted = cipher.encryptBlock(blocks[i]);
            printBlock(blocks[i], "Bloque original " + to_string(i));
            printBlock(encrypted, "Bloque cifrado " + to_string(i));
            encryptedBlocks.push_back(encrypted);
            cout << "***block "<< i <<"/"<<blocks.size()<<" encrypted ***"<<endl;
        
        }

        FileHandler::writeBlocksToFile(filenameOutput, encryptedBlocks);
    } else if (endsWith(filename,".aes")) {
            
            //decipher
            string keyFilename = argv[3];
            vector<unsigned char> key = loadKeyFromFile(keyFilename);
            AESDecipher decipher(key);
            
            vector<vector<unsigned char>> decryptedBlocks;
            for (size_t i = 0; i < blocks.size(); i++) {
                vector<unsigned char> decrypted = decipher.decryptBlock(blocks[i]);
                printBlock(blocks[i], "Bloque cifrado " + std::to_string(i));
                printBlock(decrypted, "Bloque descifrado " + std::to_string(i));
                decryptedBlocks.push_back(decrypted);
                cout << "*** Bloque " << i + 1 << "/" << blocks.size() << " descifrado ***" << endl;
            }
            FileHandler::writeBlocksToFile(filenameOutput, decryptedBlocks);

    } else{
            cerr << "Extension de archivo no reconocida. Use .txt para cifrar o .aes para descifrar." << endl;
            return 1;
    }
        
    return 0;
}
