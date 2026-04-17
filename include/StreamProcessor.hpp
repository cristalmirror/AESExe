#pragma once
#include "ICipher.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>

class StreamProcessor {
public:
    static void process(ICipher& cipher, std::istream& in, std::ostream& out, bool encrypt) {
        size_t bSize = cipher.getBlockSize();
        std::vector<uint8_t> buffer(bSize);

        while (in.read(reinterpret_cast<char*>(buffer.data()), bSize) || in.gcount() > 0) {
            std::streamsize bytesRead = in.gcount();
            if (bytesRead < static_cast<std::streamsize>(bSize)) {
                std::fill(buffer.begin() + bytesRead, buffer.end(), 0);
            }
            std::vector<uint8_t> result(bSize);
            if (encrypt) cipher.encryptBlock(buffer.data(), result.data());
            else cipher.decryptBlock(buffer.data(), result.data());
            out.write(reinterpret_cast<char*>(result.data()), bSize);
        }
    }
};
