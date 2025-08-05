#include "sm3_simd.h"
#include <cstring>
#include <cstdio>
#include <immintrin.h>

// 初始化轮常数
void init_T(uint32_t T[64]) {
    for (int i = 0; i < 16; i++) T[i] = 0x79cc4519;
    for (int i = 16; i < 64; i++) T[i] = 0x7a879d8a;
}

SM3_SIMD::SM3_SIMD() {
    reset();
}

void SM3_SIMD::reset() {
    // 初始化哈希初值 (IV)
    hash[0] = 0x7380166f;
    hash[1] = 0x4914b2b9;
    hash[2] = 0x172442d7;
    hash[3] = 0xda8a0600;
    hash[4] = 0xa96f30bc;
    hash[5] = 0x163138aa;
    hash[6] = 0xe38dee4d;
    hash[7] = 0xb0fb0e4e;

    init_T(T);
    buffer.clear();
    totalLen = 0;
    finalized = false;
}

uint32_t SM3_SIMD::rotate_left(uint32_t a, int k) const {
    k %= 32;
    return (a << k) | (a >> (32 - k));
}

uint32_t SM3_SIMD::FF(uint32_t X, uint32_t Y, uint32_t Z, int j) const {
    if (j >= 0 && j < 16)
        return X ^ Y ^ Z;
    else
        return (X & Y) | (X & Z) | (Y & Z);
}

uint32_t SM3_SIMD::GG(uint32_t X, uint32_t Y, uint32_t Z, int j) const {
    if (j >= 0 && j < 16)
        return X ^ Y ^ Z;
    else
        return (X & Y) | ((~X) & Z);
}

uint32_t SM3_SIMD::P_0(uint32_t X) const {
    return X ^ rotate_left(X, 9) ^ rotate_left(X, 17);
}

uint32_t SM3_SIMD::P_1(uint32_t X) const {
    return X ^ rotate_left(X, 15) ^ rotate_left(X, 23);
}

void SM3_SIMD::update(const uint8_t* data, size_t len) {
    totalLen += len;
    buffer.insert(buffer.end(), data, data + len);

    while (buffer.size() >= 64) {
        processBlock(buffer.data());
        buffer.erase(buffer.begin(), buffer.begin() + 64);
    }
}

void SM3_SIMD::update(const std::vector<uint8_t>& data) {
    update(data.data(), data.size());
}

void SM3_SIMD::update(const std::string& data) {
    update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

void SM3_SIMD::pad() {
    size_t len = buffer.size();
    buffer.push_back(0x80); // 加1
    while ((buffer.size() + 8) % 64 != 0) {
        buffer.push_back(0x00); // 补0
    }

    uint64_t bitLen = totalLen * 8;
    for (int i = 7; i >= 0; i--) {
        buffer.push_back((bitLen >> (i * 8)) & 0xFF);
    }

    for (size_t i = 0; i < buffer.size(); i += 64) {
        processBlock(&buffer[i]);
    }
}

void SM3_SIMD::finalize(uint8_t hash_out[32]) {
    if (!finalized) {
        pad();
        for (int i = 0; i < 8; i++) {
            hash_out[i * 4 + 0] = (hash[i] >> 24) & 0xFF;
            hash_out[i * 4 + 1] = (hash[i] >> 16) & 0xFF;
            hash_out[i * 4 + 2] = (hash[i] >> 8) & 0xFF;
            hash_out[i * 4 + 3] = (hash[i]) & 0xFF;
        }
        finalized = true;
    }
}

std::vector<uint8_t> SM3_SIMD::digest() {
    uint8_t hash_out[32];
    finalize(hash_out);
    return std::vector<uint8_t>(hash_out, hash_out + 32);
}

void SM3_SIMD::processBlock(const uint8_t block[64]) {
    uint32_t W[68] = { 0 };
    uint32_t W_1[64] = { 0 };

    // 将消息块转换为大端字
    for (int i = 0; i < 16; i++) {
        W[i] = (block[i * 4] << 24) |
            (block[i * 4 + 1] << 16) |
            (block[i * 4 + 2] << 8) |
            (block[i * 4 + 3]);
    }

    // 消息扩展，利用 SSE 优化部分
    // 这里演示一个简单的SSE辅助旋转实现，你也可以用 _mm_xor_si128 等做更复杂并行
    for (int j = 16; j < 68; j++) {
        uint32_t tmp = P_1(W[j - 16] ^ W[j - 9] ^ rotate_left(W[j - 3], 15));
        W[j] = tmp ^ rotate_left(W[j - 13], 7) ^ W[j - 6];
    }

    for (int j = 0; j < 64; j++) {
        W_1[j] = W[j] ^ W[j + 4];
    }

    uint32_t A = hash[0];
    uint32_t B = hash[1];
    uint32_t C = hash[2];
    uint32_t D = hash[3];
    uint32_t E = hash[4];
    uint32_t F = hash[5];
    uint32_t G = hash[6];
    uint32_t H = hash[7];

    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = rotate_left((rotate_left(A, 12) + E + rotate_left(T[j], j)) & 0xFFFFFFFF, 7);
        uint32_t SS2 = SS1 ^ rotate_left(A, 12);
        uint32_t TT1 = (FF(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF;
        uint32_t TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;

        D = C;
        C = rotate_left(B, 9);
        B = A;
        A = TT1;

        H = G;
        G = rotate_left(F, 19);
        F = E;
        E = P_0(TT2);
    }

    // 更新中间哈希值
    hash[0] ^= A;
    hash[1] ^= B;
    hash[2] ^= C;
    hash[3] ^= D;
    hash[4] ^= E;
    hash[5] ^= F;
    hash[6] ^= G;
    hash[7] ^= H;
}
