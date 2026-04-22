#pragma once
#include "AES.hpp"
#include <vector>
#include <algorithm>

/*
    Esta clase contiene la logica del
    algoritmo de cifrado AES128
*/
class AES256 : public AES {
public:
//constructor
    AES256(const std::vector<uint8_t>& key) {
        expandKey(key);
    }

    /*algoritmo de cifrado*/
    void encryptBlock(const uint8_t* in, uint8_t* out) override {
        uint8_t state[16];
        std::copy(in, in + 16, state);
        addRoundKey(state, roundKeys[0].data());
        for (int i = 1; i <= 13; ++i) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys[i].data());
        }
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys[14].data());
        std::copy(state, state + 16, out);
    }
    /*algoritmo de decifrado*/
    void decryptBlock(const uint8_t* in, uint8_t* out) override {
        uint8_t state[16];
        std::copy(in, in + 16, state);
        addRoundKey(state, roundKeys[14].data());
        invShiftRows(state);
        invSubBytes(state);
        for (int i = 13; i >= 1; --i) {
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
        roundKeys.assign(15, std::vector<uint8_t>(16));
        std::vector<uint8_t> exp(240);
        std::copy(key.begin(), key.end(), exp.begin());
        uint8_t rcon = 0x01;
        for (int i = 32; i < 240; i += 4) {
            //rotacion + sustitucion + XOR con Rcon
            std::vector<uint8_t> temp(exp.begin() + i - 4, exp.begin() + i);
            if (i % 32 == 0) {
                std::rotate(temp.begin(), temp.begin() + 1, temp.end());
                for (auto& b : temp) b = sbox[b];
                temp[0] ^= rcon;
                rcon = xtime(rcon);
            } else if(i % 32 == 16) {
                //sustitucion extra solo en AES256
                for (auto &b: temp) b = sbox[b];
            }

            for (int j = 0; j < 4; ++j) 
                exp[i + j] = exp[i - 32 + j] ^ temp[j];
        }
        for (int i = 0; i < 15; ++i)
            std::copy(exp.begin() + i * 16, exp.begin() + i * 16 + 16, roundKeys[i].begin());
    }
};