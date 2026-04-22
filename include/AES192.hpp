#pragma once
#include "AES.hpp"
#include <vector>
#include <algorithm>

class AES192 : public AES {
    public:
    //constructor
    AES192(const std::vector<uint8_t>& key) {
        expandKey(key);
    }

    /*algoritmo de cifrado*/
    void encryptBlock(const uint8_t* in, uint8_t* out) override {
        uint8_t state[16];
        std::copy(in, in + 16, state);
        addRoundKey(state, roundKeys[0].data());
        for (int i = 1; i <= 11; ++i) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys[i].data());
        }
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys[12].data());
        std::copy(state, state + 16, out);
    }
    /*algoritmo de decifrado*/
    void decryptBlock(const uint8_t* in, uint8_t* out) override {
        uint8_t state[16];
        std::copy(in, in + 16, state);
        addRoundKey(state, roundKeys[12].data());
        invShiftRows(state);
        invSubBytes(state);
        for (int i = 11; i >= 1; --i) {
            addRoundKey(state, roundKeys[i].data());
            invMixColumns(state);
            invShiftRows(state);
            invSubBytes(state);
        }
        addRoundKey(state, roundKeys[0].data());
        std::copy(state, state + 16, out);
    }

    size_t getBlockSize() const override { return 16; }

    protected:
    void expandKey(const std::vector<uint8_t>& key) {
        roundKeys.assign(13, std::vector<uint8_t>(16));
        std::vector<uint8_t> exp(208);
        std::copy(key.begin(), key.end(), exp.begin());
        uint8_t rcon = 0x01;
        for (int i = 24; i < 208; i += 4) {
            std::vector<uint8_t> temp(exp.begin() + i - 4, exp.begin() + i);
            if (i % 24 == 0) {
                std::rotate(temp.begin(), temp.begin() + 1, temp.end());
                for (auto& b : temp) b = sbox[b];
                temp[0] ^= rcon;
                rcon = xtime(rcon);
            }
            for (int j = 0; j < 4; ++j) exp[i + j] = exp[i - 24 + j] ^ temp[j];
        }
        for (int i = 0; i < 13; ++i)
            std::copy(exp.begin() + i * 16, exp.begin() + i * 16 + 16, roundKeys[i].begin());
    }
};