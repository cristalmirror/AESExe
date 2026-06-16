#include "../include/StreamProcessorGCM.hpp"
#include <algorithm>
#include <cstring>
#include <openssl/rand.h>

// ─── GF(2¹²⁸) ────────────────────────────────────────────────────────────────

/*
    Multiplicación en GF(2¹²⁸) siguiendo NIST SP 800-38D.

    Convención de bits: el bit más significativo del primer byte es el bit 0
    del polinomio (índice más bajo). El desplazamiento a la derecha en el campo
    corresponde a dividir por x.

    Polinomio irreducible: x¹²⁸ + x⁷ + x² + x + 1
    En el primer byte, eso equivale a XOR con 0xE1 cuando el bit sobrante es 1.
*/
void StreamProcessorGCM::gmul128(const uint8_t X[16], const uint8_t Y[16], uint8_t Z[16]) {
    uint8_t z[16] = {};
    uint8_t v[16];
    std::copy(Y, Y + 16, v);

    for (int i = 0; i < 128; i++) {
        // Si el bit i de X está encendido, acumular V en Z
        if ((X[i / 8] >> (7 - (i % 8))) & 1)
            for (int j = 0; j < 16; j++) z[j] ^= v[j];

        // Desplazar V un bit a la derecha dentro del campo
        uint8_t lsb = v[15] & 1;
        for (int j = 15; j > 0; j--)
            v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        v[0] >>= 1;

        // Si el bit que salió era 1, reducir con el polinomio irreducible
        if (lsb) v[0] ^= 0xE1;
    }
    std::copy(z, z + 16, Z);
}

// ─── GHASH ───────────────────────────────────────────────────────────────────

/*
    Evalúa GHASH_H sobre `data` usando el método de Horner:
        Y0 = 0
        Yi = (Y(i-1) XOR Xi) * H

    `len` debe ser múltiplo de 16: el caller es responsable del padding.
*/
void StreamProcessorGCM::ghash(const uint8_t H[16], const uint8_t* data,
                                size_t len, uint8_t out[16]) {
    uint8_t y[16] = {};
    for (size_t i = 0; i < len; i += 16) {
        for (int j = 0; j < 16; j++) y[j] ^= data[i + j];
        gmul128(y, H, y);
    }
    std::copy(y, y + 16, out);
}

// ─── Utilidades de contador ───────────────────────────────────────────────────

// Incrementa los últimos 32 bits del bloque contador (big-endian)
void StreamProcessorGCM::inc32(uint8_t block[16]) {
    for (int i = 15; i >= 12; i--)
        if (++block[i]) break;
}

// ─── GCTR (modo contador) ─────────────────────────────────────────────────────

/*
    Modo CTR: cifra bloques de contador con AES y hace XOR con el dato.
    Cifrar y descifrar son la misma operación.
    Soporta longitudes que no son múltiplo de 16 (último bloque parcial).
*/
void StreamProcessorGCM::gctr(ICipher& cipher, const uint8_t icb[16],
                               const uint8_t* in, uint8_t* out, size_t len) {
    uint8_t cb[16];
    std::copy(icb, icb + 16, cb);
    uint8_t ks[16];

    size_t offset = 0;
    while (offset < len) {
        cipher.encryptBlock(cb, ks);
        size_t chunk = std::min(len - offset, size_t(16));
        for (size_t j = 0; j < chunk; j++)
            out[offset + j] = in[offset + j] ^ ks[j];
        offset += chunk;
        inc32(cb);
    }
}

// ─── Encrypt ─────────────────────────────────────────────────────────────────

bool StreamProcessorGCM::encrypt(ICipher& cipher, std::istream& in, std::ostream& out) {
    // Nonce único de 96 bits por operación
    uint8_t nonce[NONCE_SIZE];
    if (RAND_bytes(nonce, NONCE_SIZE) != 1) return false;

    std::vector<uint8_t> plaintext(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>()
    );
    size_t pLen = plaintext.size();

    // H = AES_K(0¹²⁸)
    uint8_t zero[16] = {}, H[16];
    cipher.encryptBlock(zero, H);

    // J0 = nonce || 0x00000001
    uint8_t J0[16] = {};
    std::copy(nonce, nonce + NONCE_SIZE, J0);
    J0[15] = 0x01;

    // Cifrar con CTR empezando en inc32(J0) = nonce || 0x00000002
    uint8_t icb[16];
    std::copy(J0, J0 + 16, icb);
    inc32(icb);

    std::vector<uint8_t> ciphertext(pLen);
    gctr(cipher, icb, plaintext.data(), ciphertext.data(), pLen);

    // Entrada para GHASH: [ciphertext padded a múltiplo de 16] [len(AAD)=0 · 8 bytes] [len(C) en bits · 8 bytes]
    size_t cPadLen = ((pLen + 15) / 16) * 16;
    std::vector<uint8_t> ghashInput(cPadLen + 16, 0x00);
    std::copy(ciphertext.begin(), ciphertext.end(), ghashInput.begin());

    uint64_t cBits = static_cast<uint64_t>(pLen) * 8;
    for (int i = 7; i >= 0; i--) {
        ghashInput[cPadLen + 8 + i] = cBits & 0xFF;
        cBits >>= 8;
    }

    uint8_t S[16];
    ghash(H, ghashInput.data(), ghashInput.size(), S);

    // Tag = AES_K(J0) XOR S
    uint8_t EJ0[16], tag[TAG_SIZE];
    cipher.encryptBlock(J0, EJ0);
    for (int i = 0; i < TAG_SIZE; i++) tag[i] = EJ0[i] ^ S[i];

    // [nonce (12)] [ciphertext] [tag (16)]
    out.write(reinterpret_cast<char*>(nonce), NONCE_SIZE);
    out.write(reinterpret_cast<char*>(ciphertext.data()), static_cast<std::streamsize>(pLen));
    out.write(reinterpret_cast<char*>(tag), TAG_SIZE);
    return out.good();
}

// ─── Decrypt ─────────────────────────────────────────────────────────────────

bool StreamProcessorGCM::decrypt(ICipher& cipher, std::istream& in, std::ostream& out) {
    std::vector<uint8_t> input(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>()
    );

    if (static_cast<int>(input.size()) < NONCE_SIZE + TAG_SIZE) return false;

    const uint8_t* nonce      = input.data();
    const uint8_t* ciphertext = input.data() + NONCE_SIZE;
    const size_t   cLen       = input.size() - NONCE_SIZE - TAG_SIZE;
    const uint8_t* tag_recv   = input.data() + NONCE_SIZE + cLen;

    // H = AES_K(0¹²⁸)
    uint8_t zero[16] = {}, H[16];
    cipher.encryptBlock(zero, H);

    // J0 = nonce || 0x00000001
    uint8_t J0[16] = {};
    std::copy(nonce, nonce + NONCE_SIZE, J0);
    J0[15] = 0x01;

    // Verificar tag ANTES de descifrar
    size_t cPadLen = ((cLen + 15) / 16) * 16;
    std::vector<uint8_t> ghashInput(cPadLen + 16, 0x00);
    std::copy(ciphertext, ciphertext + cLen, ghashInput.begin());

    uint64_t cBits = static_cast<uint64_t>(cLen) * 8;
    for (int i = 7; i >= 0; i--) {
        ghashInput[cPadLen + 8 + i] = cBits & 0xFF;
        cBits >>= 8;
    }

    uint8_t S[16];
    ghash(H, ghashInput.data(), ghashInput.size(), S);

    uint8_t EJ0[16], tag_calc[TAG_SIZE];
    cipher.encryptBlock(J0, EJ0);
    for (int i = 0; i < TAG_SIZE; i++) tag_calc[i] = EJ0[i] ^ S[i];

    // Comparación en tiempo constante (evita timing attacks)
    uint8_t diff = 0;
    for (int i = 0; i < TAG_SIZE; i++) diff |= tag_calc[i] ^ tag_recv[i];
    if (diff != 0) return false;

    // Descifrar con CTR (misma operación que cifrar)
    uint8_t icb[16];
    std::copy(J0, J0 + 16, icb);
    inc32(icb);

    std::vector<uint8_t> plaintext(cLen);
    gctr(cipher, icb, ciphertext, plaintext.data(), cLen);

    out.write(reinterpret_cast<char*>(plaintext.data()), static_cast<std::streamsize>(cLen));
    return out.good();
}
