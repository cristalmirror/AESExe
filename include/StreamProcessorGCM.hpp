#pragma once
#include "ICipher.hpp"
#include <cstdint>
#include <istream>
#include <ostream>
#include <vector>

class StreamProcessorGCM {
public:
    static constexpr int NONCE_SIZE = 12;
    static constexpr int TAG_SIZE   = 16;

    // Formato de salida: [nonce (12 bytes)][ciphertext][tag (16 bytes)]
    static bool encrypt(ICipher& cipher, std::istream& in, std::ostream& out);

    // Retorna false si el tag no coincide (datos adulterados o clave incorrecta)
    static bool decrypt(ICipher& cipher, std::istream& in, std::ostream& out);

private:
    static void gmul128(const uint8_t X[16], const uint8_t Y[16], uint8_t Z[16]);
    static void ghash(const uint8_t H[16], const uint8_t* data, size_t len, uint8_t out[16]);
    static void gctr(ICipher& cipher, const uint8_t icb[16],
                     const uint8_t* in, uint8_t* out, size_t len);
    static void inc32(uint8_t block[16]);
};
