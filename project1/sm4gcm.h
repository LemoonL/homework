#pragma once

#include <cstdint>
#include <cstddef>
#include "sm4.h"

class sm4gcm {
public:
    sm4gcm(const uint8_t key[16], const uint8_t* iv, size_t iv_len);

    void encrypt(const uint8_t* plaintext, size_t len,
        const uint8_t* aad, size_t aad_len,
        uint8_t* ciphertext, uint8_t tag[16]);

    bool decrypt(const uint8_t* ciphertext, size_t len,
        const uint8_t* aad, size_t aad_len,
        const uint8_t tag[16], uint8_t* plaintext);

private:
    sm4 cipher;
    uint8_t H[16];    // Hash subkey
    uint8_t J0[16];   // Pre-counter block
    uint8_t counter[16]; // Current counter

    void ghash(const uint8_t* aad, size_t aad_len,
        const uint8_t* ct, size_t ct_len,
        uint8_t tag[16]);

    void gmul(uint8_t X[16], const uint8_t Y[16]);
    void xor_block(uint8_t out[16], const uint8_t in[16]);
    void inc32(uint8_t block[16]);
    void encrypt_ctr(const uint8_t* input, size_t len, uint8_t* output);
};
