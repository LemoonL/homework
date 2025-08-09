#include "sm4_gcm_opt.h"
#include <cstring>

constexpr size_t BLOCK_SIZE = 16;

sm4_gcm_opt::sm4_gcm_opt(const uint8_t key[16], const uint8_t* iv, size_t iv_len) {
    cipher.setKey(key);

    uint8_t zero[BLOCK_SIZE] = { 0 };
    cipher.encryptBlock(zero, H);

    if (iv_len == 12) {
        std::memcpy(J0, iv, 12);
        J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
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
        uint64_t iv_bits = iv_len * 8;
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

inline void sm4_gcm_opt::xor_block(uint8_t out[16], const uint8_t in[16]) {
    auto* out64 = reinterpret_cast<uint64_t*>(out);
    const auto* in64 = reinterpret_cast<const uint64_t*>(in);
    out64[0] ^= in64[0];
    out64[1] ^= in64[1];
}

inline void sm4_gcm_opt::inc32(uint8_t block[16]) {
    for (int i = 15; i >= 12; --i) {
        if (++block[i] != 0) break;
    }
}

inline void sm4_gcm_opt::gmul(uint8_t X[16], const uint8_t Y[16]) {
    uint8_t Z[16] = { 0 };
    uint8_t V[16];
    std::memcpy(V, Y, BLOCK_SIZE);

    for (int i = 0; i < 128; ++i) {
        int bit = (X[i / 8] >> (7 - (i % 8))) & 1;
        if (bit) {
            for (int j = 0; j < 16; ++j)
                Z[j] ^= V[j];
        }
        bool lsb = (V[15] & 1) != 0;
        for (int j = 15; j > 0; --j)
            V[j] = (V[j] >> 1) | ((V[j - 1] & 1) << 7);
        V[0] >>= 1;
        if (lsb) V[0] ^= 0xe1;
    }
    std::memcpy(X, Z, BLOCK_SIZE);
}

void sm4_gcm_opt::encrypt_ctr(const uint8_t* input, size_t len, uint8_t* output) {
    uint8_t keystream[BLOCK_SIZE];

    size_t blocks = len / BLOCK_SIZE;
    size_t rem = len % BLOCK_SIZE;

    for (size_t i = 0; i < blocks; ++i) {
        cipher.encryptBlock(counter, keystream);
        for (size_t j = 0; j < BLOCK_SIZE; ++j)
            output[i * BLOCK_SIZE + j] = input[i * BLOCK_SIZE + j] ^ keystream[j];
        inc32(counter);
    }
    if (rem) {
        cipher.encryptBlock(counter, keystream);
        for (size_t j = 0; j < rem; ++j)
            output[blocks * BLOCK_SIZE + j] = input[blocks * BLOCK_SIZE + j] ^ keystream[j];
        inc32(counter);
    }
}

void sm4_gcm_opt::ghash(const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    uint8_t tag[16]) {
    uint8_t Y[BLOCK_SIZE] = { 0 };

    size_t aad_blocks = aad_len / BLOCK_SIZE;
    size_t aad_rem = aad_len % BLOCK_SIZE;
    for (size_t i = 0; i < aad_blocks; ++i) {
        xor_block(Y, aad + i * BLOCK_SIZE);
        gmul(Y, H);
    }
    if (aad_rem) {
        uint8_t last[BLOCK_SIZE] = { 0 };
        std::memcpy(last, aad + aad_blocks * BLOCK_SIZE, aad_rem);
        xor_block(Y, last);
        gmul(Y, H);
    }

    size_t ct_blocks = ct_len / BLOCK_SIZE;
    size_t ct_rem = ct_len % BLOCK_SIZE;
    for (size_t i = 0; i < ct_blocks; ++i) {
        xor_block(Y, ct + i * BLOCK_SIZE);
        gmul(Y, H);
    }
    if (ct_rem) {
        uint8_t last[BLOCK_SIZE] = { 0 };
        std::memcpy(last, ct + ct_blocks * BLOCK_SIZE, ct_rem);
        xor_block(Y, last);
        gmul(Y, H);
    }

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

void sm4_gcm_opt::encrypt(const uint8_t* plaintext, size_t len,
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

bool sm4_gcm_opt::decrypt(const uint8_t* ciphertext, size_t len,
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
    for (int i = 0; i < 16; ++i) {
        diff |= (computed_tag[i] ^ tag[i]);
    }
    return diff == 0;
}