#pragma once

#include <cstdint>
#include <cstddef>
#include <wmmintrin.h>  // PCLMULQDQ + SSE intrinsics
#include "sm4.h"

// Note: compile with -msse4.1 -mpclmul (GCC/Clang)

class sm4_gcm_simd {
public:
    sm4_gcm_simd(const uint8_t key[16], const uint8_t* iv, size_t iv_len);

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
    uint8_t counter[16]; 

    void ghash(const uint8_t* aad, size_t aad_len,
        const uint8_t* ct, size_t ct_len,
        uint8_t tag[16]);

    void gmul(uint8_t X[16], const uint8_t Y[16]); // X = X * Y in GF(2^128)
    void xor_block(uint8_t out[16], const uint8_t in[16]);
    void inc32(uint8_t block[16]);
    void encrypt_ctr(const uint8_t* input, size_t len, uint8_t* output);

    // SIMD helpers
    static inline __m128i load128(const uint8_t* b);
    static inline void store128(uint8_t* b, __m128i v);
    static inline __m128i ghash_multiply(__m128i a, __m128i b);
    static inline __m128i xor128(__m128i a, __m128i b);
};
