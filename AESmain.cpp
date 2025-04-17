#include<iostream>
#include<fstream>
#include<vector>
#include<cstring>
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
//function main 
int main(int argc,char *argv[]) {
    
    if (argc < 2) {
        cerr <<"Uso: "<< argv[0] << "<nombre_de_archivo.txt>"<< endl;
        return 1;
    }

    string filename = argv[1];
    string binaryFilenameOutput = argv[2];
    binaryFilenameOutput = binaryFilenameOutput + ".aes";
    vector<vector<unsigned char>> blocks =FileHandler::readFileInBlocks(filename);
    vector<vector<unsigned char>> encryptedBlocks;
    cout <<"se leyeron "<< blocks.size() << " bloques de "<< BLOCK_SIZE <<"bytes." << endl;

    //Key AES of 16 bytes
    vector<unsigned char> key = generateSaveKeyBase("key.aes");
    AESCipher cipher(key);
    
    //cipher and write blocks
    for (size_t i = 0; i < blocks.size(); i++) {
        vector<unsigned char> encrypted = cipher.encryptBlock(blocks[i]);
        encryptedBlocks.push_back(encrypted);
        cout << "***block "<< i <<"/"<<blocks.size()<<" encrypted ***"<<endl;
        
    }

    FileHandler::writeBlocksToFile(binaryFilenameOutput, encryptedBlocks);
    return 0;
}
