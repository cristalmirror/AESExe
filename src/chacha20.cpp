
#include <vector>
#include <cstdint>
#include "../include/chacha20.hpp"

ChaCha20::ChaCha20(const std::vector<uint8_t> &key) {
    for (int i = 0; i < 16; i++) state[i] = 0;
    setupInitialState(key);
}

void ChaCha20::setupInitialState(const std::vector<unsigned char> &key) {
    //palabras constantes 0-3 
    state[0] = 0x61707865;
    state[1] = 0x3320646e; 
    state[2] = 0x79622d32; 
    state[3] = 0x6b206574;

    // palabras 4-11 key de 32 bytes
    for (int i = 0; i < 8; i++) {
        state[4 + i] = key[i*4] | (key[i*4+1] << 8) | (key[i*4+2] << 16) | (key[i*4+3] << 24);
    }

    //counter block (conter block fue eliminado por ser remplazable por un valor fijo)
    state[12] = conter;

    //palabras del nonce
    for (int i = 0; i < 3; i++){
        state[13 + i] = nonce[i*4] | (nonce[i*4+1] << 8) | (nonce[i*4+2] << 16) | (nonce[i*4+3] << 24);
    }

}
/*
    rotacion a la izquierda
    v << c → desplaza c bits a la izquierda (los bits que sobran se pierden)
    v >> (32 - c) → desplaza los bits restantes a la derecha, recuperando los que "cayeron"
    | → los une
*/
uint32_t ChaCha20::ROTL(uint32_t v, int c) {
    return (v << c) | (v >> (32 - c));
}

/*
    operaciones ARX sobre los
    elementos originales de l
    os bloques, (Add-Rotate-XOR)
*/
void ChaCha20::quarterRound(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    a += b; d ^= a; d = ROTL(d, 16);
    c += d; b ^= c; b = ROTL(b, 12);
    a += b; d ^= a; d = ROTL(d, 8);
    c += d; b ^= c; b = ROTL(b, 7);
}

void ChaCha20::encryptBlock(const uint8_t *in, uint8_t *out) {
    uint32_t workingState[16];
    uint32_t initialState[16];

    for (int i = 0; i < 16; i++) initialState[i] = workingState[i] = state[i];

    // 20 rondas
    for (int i = 0; i < 10; i++) {
        // Columnas
        quarterRound(workingState[0], workingState[4], workingState[8],  workingState[12]);
        quarterRound(workingState[1], workingState[5], workingState[9],  workingState[13]);
        quarterRound(workingState[2], workingState[6], workingState[10], workingState[14]);
        quarterRound(workingState[3], workingState[7], workingState[11], workingState[15]);
        // Diagonales
        quarterRound(workingState[0], workingState[5], workingState[10], workingState[15]);
        quarterRound(workingState[1], workingState[6], workingState[11], workingState[12]);
        quarterRound(workingState[2], workingState[7], workingState[8],  workingState[13]);
        quarterRound(workingState[3], workingState[4], workingState[9],  workingState[14]);
    }

    for (int i = 0; i < 16; i++) workingState[i] += initialState[i];

    // XOR: ahora lee de "in" y escribe en "out" en lugar de modificar el vector
    for (int i = 0; i < 64; i++) {
        out[i] = in[i] ^ ((workingState[i / 4] >> (8 * (i % 4))) & 0xFF);
    }

    state[12]++;
}

void ChaCha20::decryptBlock(const uint8_t *in, uint8_t *out) {
    encryptBlock(in,out);
}