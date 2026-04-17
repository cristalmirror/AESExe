#pragma once
#include <cstdint>
#include <vector>
#include <cstddef>

class ICipher {
public:
    virtual ~ICipher() = default;
    virtual void encryptBlock(const uint8_t* in, uint8_t* out) = 0;
    virtual void decryptBlock(const uint8_t* in, uint8_t* out) = 0;
    virtual size_t getBlockSize() const = 0;
};
