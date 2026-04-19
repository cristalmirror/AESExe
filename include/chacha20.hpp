#ifndef CHACHA20_HPP
#define CHACHA20_HPP
#include <vector>
#include <cstdint>
#include "ICipher.hpp"


class ChaCha20 : public ICipher {
    private:
    uint32_t conter = 1;
    std::vector<uint8_t> nonce = {0,0,0,0, 0,0,0,0, 0,0,0,0};
    uint32_t state[16];//internal state 512 bits
    uint32_t ROTL(uint32_t v, int c);
    void quarterRound(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d);
    void setupInitialState(const std::vector<unsigned char> &key);
    
    public:
    size_t getBlockSize() const override {return 64;};
    void encryptBlock(const uint8_t *in, uint8_t *out) override;
    void decryptBlock(const uint8_t *in, uint8_t *out) override;
    ChaCha20(const std::vector<uint8_t> &key);
    ~ChaCha20() = default;
};

#endif
