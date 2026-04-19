#pragma once
#include "ICipher.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
/*
    esta clase se va a encargar de gestionar los archivos
    de entrada y salida y una instancia de alguna clase que
    implemente ICipher (AES128,256,chacha20,etc).
*/
class StreamProcessor {
public:
    static void process(ICipher& cipher, std::istream& in, std::ostream& out, bool encrypt) {
        size_t bSize = cipher.getBlockSize(); //tamaño del bloque
        std::vector<uint8_t> buffer(bSize);
        
        /*
            Lee mientra no se llegue llegue al final
            del archivo, partiendo bSize bytes y los pone
            en el buffer, luego se convierte el buffer de 
            uint8_t a char y se rellena de 0 el ultimo bloque
            si no es multiplo de bSize(null padding)

            Luego decide si se cifra o decifra el bloque
            y finalmente lo escribe en el archivo de salida
        */
        while (in.read(reinterpret_cast<char*>(buffer.data()), bSize) || in.gcount() > 0) {
            std::streamsize bytesRead = in.gcount();
            if (bytesRead < static_cast<std::streamsize>(bSize)) {//condicion de null padding
                std::fill(buffer.begin() + bytesRead, buffer.end(), 0);
            }
            std::vector<uint8_t> result(bSize);//bloque resultado
            
            //opcion de cifrado o decifrado
            if (encrypt) cipher.encryptBlock(buffer.data(), result.data());
            else cipher.decryptBlock(buffer.data(), result.data());
            out.write(reinterpret_cast<char*>(result.data()), bSize); //manejo del archivo de salida
        }
    }
};
