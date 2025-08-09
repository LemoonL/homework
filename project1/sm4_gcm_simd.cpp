#include "sm4_gcm_simd.h"
#include <cstring>
#include <emmintrin.h>
#include <tmmintrin.h> // _mm_shuffle_epi8
#include <smmintrin.h>
#include <wmmintrin.h>

constexpr size_t BLOCK_SIZE = 16;

// ---------------- SIMD helpers ----------------

inline __m128i sm4_gcm_simd::load128(const uint8_t* b) {
    return _mm_loadu_si128(reinterpret_cast<const __m128i*>(b));
}
inline void sm4_gcm_simd::store128(uint8_t* b, __m128i v) {
    _mm_storeu_si128(reinterpret_cast<__m128i*>(b), v);
}
inline __m128i sm4_gcm_simd::xor128(__m128i a, __m128i b) {
    return _mm_xor_si128(a, b);
}

/*
  ghash_multiply: full CLMUL product + reduction
  This follows the algorithmic sequence shown in Intel whitepaper (Figures 5/7),
  which yields an exact 128-bit result equivalent to canonical software GF(2^128) product
  reduced modulo x^128 + x^7 + x^2 + x + 1.
*/
inline __m128i sm4_gcm_simd::ghash_multiply(__m128i a, __m128i b) {
    // carry-less multiply parts
    __m128i tmp3 = _mm_clmulepi64_si128(a, b, 0x00); // a_lo * b_lo
    __m128i tmp4 = _mm_clmulepi64_si128(a, b, 0x10); // a_hi * b_lo
    __m128i tmp5 = _mm_clmulepi64_si128(a, b, 0x01); // a_lo * b_hi
    __m128i tmp6 = _mm_clmulepi64_si128(a, b, 0x11); // a_hi * b_hi

    // combine middle parts
    tmp4 = _mm_xor_si128(tmp4, tmp5);   // middle combined

    // fold middle into low/high 128-bit halves
    __m128i t_lo = _mm_slli_si128(tmp4, 8); // middle << 64
    __m128i t_hi = _mm_srli_si128(tmp4, 8); // middle >> 64

    tmp3 = _mm_xor_si128(tmp3, t_lo);   // low 128 bits
    tmp6 = _mm_xor_si128(tmp6, t_hi);   // high 128 bits

    // Now tmp6: high 128 bits, tmp3: low 128 bits -> 256-bit product = (tmp6,tmp3)

    // Begin reduction (two-phase) as in Intel paper:
    // Phase 1: bit-manipulation and alignment
    __m128i tmp7 = _mm_srli_epi32(tmp3, 31);
    __m128i tmp8 = _mm_srli_epi32(tmp6, 31);

    tmp3 = _mm_slli_epi32(tmp3, 1);
    tmp6 = _mm_slli_epi32(tmp6, 1);

    __m128i tmp9 = _mm_srli_si128(tmp7, 12);
    tmp8 = _mm_slli_si128(tmp8, 4);
    tmp7 = _mm_slli_si128(tmp7, 4);

    tmp3 = _mm_or_si128(tmp3, tmp7);
    tmp6 = _mm_or_si128(tmp6, tmp8);
    tmp6 = _mm_or_si128(tmp6, tmp9);

    // Phase 2: more folding for reduction
    __m128i t7 = _mm_slli_epi32(tmp3, 31);
    __m128i t8 = _mm_slli_epi32(tmp3, 30);
    __m128i t9 = _mm_slli_epi32(tmp3, 25);

    t7 = _mm_xor_si128(t7, t8);
    t7 = _mm_xor_si128(t7, t9);

    __m128i t8_shifted = _mm_srli_si128(t7, 4);
    t7 = _mm_slli_si128(t7, 12);

    tmp3 = _mm_xor_si128(tmp3, t7);

    __m128i tmp2 = _mm_srli_epi32(tmp3, 1);
    __m128i tmp4_2 = _mm_srli_epi32(tmp3, 2);
    __m128i tmp5_2 = _mm_srli_epi32(tmp3, 7);

    tmp2 = _mm_xor_si128(tmp2, tmp4_2);
    tmp2 = _mm_xor_si128(tmp2, tmp5_2);
    tmp2 = _mm_xor_si128(tmp2, t8_shifted);

    tmp3 = _mm_xor_si128(tmp3, tmp2);

    tmp6 = _mm_xor_si128(tmp6, tmp3);

    // tmp6 now holds the reduced 128-bit result
    return tmp6;
}


sm4_gcm_simd::sm4_gcm_simd(const uint8_t key[16], const uint8_t* iv, size_t iv_len) {
    cipher.setKey(key);

    uint8_t zero[BLOCK_SIZE] = { 0 };
    cipher.encryptBlock(zero, H);

    if (iv_len == 12) {
        std::memcpy(J0, iv, 12);
        J0[12] = 0x00; J0[13] = 0x00; J0[14] = 0x00; J0[15] = 0x01;
    }
    else {
        uint8_t S[BLOCK_SIZE] = { 0 };
        size_t blocks = iv_len / BLOCK_SIZE;
        size_t rem = iv_len % BLOCK_SIZE;
        for (size_t i = 0; i < blocks; ++i) {
            xor_block(S, iv + i * BLOCK_SIZE);
            gmul(S, H);
        }
        if (rem) {
            uint8_t last[BLOCK_SIZE] = { 0 };
            std::memcpy(last, iv + blocks * BLOCK_SIZE, rem);
            xor_block(S, last);
            gmul(S, H);
        }

        uint8_t len_block[BLOCK_SIZE] = { 0 };
        uint64_t iv_bits = static_cast<uint64_t>(iv_len) * 8;
        for (int i = 0; i < 8; ++i) {
            len_block[15 - i] = static_cast<uint8_t>(iv_bits & 0xff);
            iv_bits >>= 8;
        }
        xor_block(S, len_block);
        gmul(S, H);
        std::memcpy(J0, S, BLOCK_SIZE);
    }
    std::memcpy(counter, J0, BLOCK_SIZE);
}

void sm4_gcm_simd::encrypt(const uint8_t* plaintext, size_t len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext, uint8_t tag[16]) {
    std::memcpy(counter, J0, BLOCK_SIZE);
    inc32(counter);

    encrypt_ctr(plaintext, len, ciphertext);
    ghash(aad, aad_len, ciphertext, len, tag);

    uint8_t Ek0[BLOCK_SIZE];
    cipher.encryptBlock(J0, Ek0);
    xor_block(tag, Ek0);
}

bool sm4_gcm_simd::decrypt(const uint8_t* ciphertext, size_t len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t tag[16], uint8_t* plaintext) {
    std::memcpy(counter, J0, BLOCK_SIZE);
    inc32(counter);

    encrypt_ctr(ciphertext, len, plaintext);

    uint8_t computed_tag[BLOCK_SIZE];
    ghash(aad, aad_len, ciphertext, len, computed_tag);

    uint8_t Ek0[BLOCK_SIZE];
    cipher.encryptBlock(J0, Ek0);
    xor_block(computed_tag, Ek0);

    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= (computed_tag[i] ^ tag[i]);
    return diff == 0;
}

void sm4_gcm_simd::encrypt_ctr(const uint8_t* input, size_t len, uint8_t* output) {
    uint8_t keystream[BLOCK_SIZE];
    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        cipher.encryptBlock(counter, keystream);
        size_t block_size = (i + BLOCK_SIZE <= len) ? BLOCK_SIZE : (len - i);
        for (size_t j = 0; j < block_size; ++j) output[i + j] = input[i + j] ^ keystream[j];
        inc32(counter);
    }
}

void sm4_gcm_simd::ghash(const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    uint8_t tag[16]) {
    uint8_t Y[BLOCK_SIZE] = { 0 };

    // process AAD
    size_t blocks = (aad_len) / BLOCK_SIZE;
    for (size_t i = 0; i < blocks; ++i) {
        xor_block(Y, aad + i * BLOCK_SIZE);
        gmul(Y, H);
    }
    if (aad_len % BLOCK_SIZE) {
        uint8_t last[BLOCK_SIZE] = { 0 };
        std::memcpy(last, aad + blocks * BLOCK_SIZE, aad_len % BLOCK_SIZE);
        xor_block(Y, last);
        gmul(Y, H);
    }

    // process ciphertext
    blocks = ct_len / BLOCK_SIZE;
    for (size_t i = 0; i < blocks; ++i) {
        xor_block(Y, ct + i * BLOCK_SIZE);
        gmul(Y, H);
    }
    if (ct_len % BLOCK_SIZE) {
        uint8_t last[BLOCK_SIZE] = { 0 };
        std::memcpy(last, ct + blocks * BLOCK_SIZE, ct_len % BLOCK_SIZE);
        xor_block(Y, last);
        gmul(Y, H);
    }

    // length block (AAD bits || CT bits), big-endian 64-bit each
    uint8_t len_block[BLOCK_SIZE] = { 0 };
    uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8;
    uint64_t ct_bits = static_cast<uint64_t>(ct_len) * 8;
    for (int i = 0; i < 8; ++i) {
        len_block[7 - i] = static_cast<uint8_t>((aad_bits >> (i * 8)) & 0xff);
        len_block[15 - i] = static_cast<uint8_t>((ct_bits >> (i * 8)) & 0xff);
    }

    xor_block(Y, len_block);
    gmul(Y, H);

    std::memcpy(tag, Y, BLOCK_SIZE);
}

void sm4_gcm_simd::xor_block(uint8_t out[16], const uint8_t in[16]) {
    for (int i = 0; i < 16; ++i) out[i] ^= in[i];
}

void sm4_gcm_simd::inc32(uint8_t block[16]) {
    for (int i = 15; i >= 12; --i) if (++block[i]) break;
}

/*
  gmul: use PCLMUL with byte-reversal so that in-register 64-bit halves line up
  with the CLMUL expectations and produce the same numeric result as software GHASH.
  We perform:
    xr = byte_reverse(X)
    yr = byte_reverse(Y)
    r = ghash_multiply(xr, yr)   // uses CLMUL & reduction
    rout = byte_reverse(r)
    store rout into X
*/
void sm4_gcm_simd::gmul(uint8_t X[16], const uint8_t Y[16]) {
    // reverse mask for _mm_shuffle_epi8: reverse bytes within 128-bit lane
    const __m128i REV = _mm_setr_epi8(
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
    );

    __m128i x = load128(X);
    __m128i y = load128(Y);

    // byte-reverse to convert big-endian (memory) -> little-endian lane order for CLMUL
    __m128i xr = _mm_shuffle_epi8(x, REV);
    __m128i yr = _mm_shuffle_epi8(y, REV);

    // CLMUL product + reduction
    __m128i r = ghash_multiply(xr, yr);

    // reverse bytes back to memory big-endian ordering
    __m128i rout = _mm_shuffle_epi8(r, REV);

    store128(X, rout);
}
