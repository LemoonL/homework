#include "sm4gcm.h"
#include <cstring>

sm4gcm::sm4gcm(const uint8_t key[16], const uint8_t* iv, size_t iv_len) {
    cipher.setKey(key);

    // H = E_k(0^128)
    uint8_t zero[16] = { 0 };
    cipher.encryptBlock(zero, H);

    // J0 = IV || 0^31 || 1  if len(IV) == 96 bits
    // Else: J0 = GHASH(IV || pad || len(IV)*8)
    if (iv_len == 12) {
        std::memcpy(J0, iv, 12);
        J0[12] = 0x00; J0[13] = 0x00; J0[14] = 0x00; J0[15] = 0x01;
    }
    else {
        uint8_t S[16] = { 0 };
        size_t rem = iv_len % 16;
        size_t blocks = iv_len / 16;
        for (size_t i = 0; i < blocks; ++i) {
            xor_block(S, iv + i * 16);
            gmul(S, H);
        }
        if (rem) {
            uint8_t last[16] = { 0 };
            std::memcpy(last, iv + blocks * 16, rem);
            xor_block(S, last);
            gmul(S, H);
        }

        uint8_t len_block[16] = { 0 };
        uint64_t iv_bits = iv_len * 8;
        len_block[8] = (iv_bits >> 56) & 0xff;
        len_block[9] = (iv_bits >> 48) & 0xff;
        len_block[10] = (iv_bits >> 40) & 0xff;
        len_block[11] = (iv_bits >> 32) & 0xff;
        len_block[12] = (iv_bits >> 24) & 0xff;
        len_block[13] = (iv_bits >> 16) & 0xff;
        len_block[14] = (iv_bits >> 8) & 0xff;
        len_block[15] = iv_bits & 0xff;

        xor_block(S, len_block);
        gmul(S, H);

        std::memcpy(J0, S, 16);
    }

    std::memcpy(counter, J0, 16);
}

void sm4gcm::encrypt(const uint8_t* plaintext, size_t len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext, uint8_t tag[16]) {
    std::memcpy(counter, J0, 16);
    inc32(counter);

    encrypt_ctr(plaintext, len, ciphertext);
    ghash(aad, aad_len, ciphertext, len, tag);

    uint8_t Ek0[16];
    cipher.encryptBlock(J0, Ek0);
    xor_block(tag, Ek0);
}

bool sm4gcm::decrypt(const uint8_t* ciphertext, size_t len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t tag[16], uint8_t* plaintext) {
    std::memcpy(counter, J0, 16);
    inc32(counter);

    encrypt_ctr(ciphertext, len, plaintext);

    uint8_t computed_tag[16];
    ghash(aad, aad_len, ciphertext, len, computed_tag);

    uint8_t Ek0[16];
    cipher.encryptBlock(J0, Ek0);
    xor_block(computed_tag, Ek0);

    return std::memcmp(computed_tag, tag, 16) == 0;
}

void sm4gcm::encrypt_ctr(const uint8_t* input, size_t len, uint8_t* output) {
    uint8_t keystream[16];
    for (size_t i = 0; i < len; i += 16) {
        cipher.encryptBlock(counter, keystream);
        size_t block_size = (i + 16 <= len) ? 16 : (len - i);
        for (size_t j = 0; j < block_size; ++j)
            output[i + j] = input[i + j] ^ keystream[j];
        inc32(counter);
    }
}

void sm4gcm::ghash(const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    uint8_t tag[16]) {
    uint8_t Y[16] = { 0 };

    // GHASH AAD
    size_t blocks = aad_len / 16;
    for (size_t i = 0; i < blocks; ++i) {
        xor_block(Y, aad + i * 16);
        gmul(Y, H);
    }
    if (aad_len % 16) {
        uint8_t last[16] = { 0 };
        std::memcpy(last, aad + blocks * 16, aad_len % 16);
        xor_block(Y, last);
        gmul(Y, H);
    }

    // GHASH ciphertext
    blocks = ct_len / 16;
    for (size_t i = 0; i < blocks; ++i) {
        xor_block(Y, ct + i * 16);
        gmul(Y, H);
    }
    if (ct_len % 16) {
        uint8_t last[16] = { 0 };
        std::memcpy(last, ct + blocks * 16, ct_len % 16);
        xor_block(Y, last);
        gmul(Y, H);
    }

    // Length block
    uint8_t len_block[16] = { 0 };
    uint64_t aad_bits = aad_len * 8;
    uint64_t ct_bits = ct_len * 8;

    for (int i = 0; i < 8; ++i) {
        len_block[7 - i] = (aad_bits >> (i * 8)) & 0xff;
        len_block[15 - i] = (ct_bits >> (i * 8)) & 0xff;
    }

    xor_block(Y, len_block);
    gmul(Y, H);

    std::memcpy(tag, Y, 16);
}

void sm4gcm::xor_block(uint8_t out[16], const uint8_t in[16]) {
    for (int i = 0; i < 16; ++i)
        out[i] ^= in[i];
}

void sm4gcm::inc32(uint8_t block[16]) {
    for (int i = 15; i >= 12; --i)
        if (++block[i]) break;
}

// GF(2^128) ³Ë·¨ (big endian)
void sm4gcm::gmul(uint8_t X[16], const uint8_t Y[16]) {
    uint8_t Z[16] = { 0 };
    uint8_t V[16];
    std::memcpy(V, Y, 16);

    for (int i = 0; i < 128; ++i) {
        int bit = (X[i / 8] >> (7 - (i % 8))) & 1;
        if (bit)
            for (int j = 0; j < 16; ++j)
                Z[j] ^= V[j];

        // Shift V right by 1
        bool lsb = V[15] & 1;
        for (int j = 15; j > 0; --j)
            V[j] = (V[j] >> 1) | ((V[j - 1] & 1) << 7);
        V[0] >>= 1;
        if (lsb)
            V[0] ^= 0xe1;  // 0xE1000000000000000000000000000000 mod poly
    }
    std::memcpy(X, Z, 16);
}
