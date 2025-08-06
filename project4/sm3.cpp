#include "sm3.h"

#include <cstring>

// 初始化向量（IV）
static const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

SM3::SM3() {
    reset();
}

void SM3::reset() {
    std::memcpy(V, IV, sizeof(IV));
    buffer.clear();
    totalLen = 0;
    finalized = false;
}

uint32_t SM3::ROTL(uint32_t x, int n) const {
    return (x << n) | (x >> (32 - n));
}

uint32_t SM3::P0(uint32_t x) const {
    return x ^ ROTL(x, 9) ^ ROTL(x, 17);
}

uint32_t SM3::P1(uint32_t x) const {
    return x ^ ROTL(x, 15) ^ ROTL(x, 23);
}

uint32_t SM3::T(int j) const {
    return j < 16 ? 0x79CC4519 : 0x7A879D8A;
}

uint32_t SM3::FF(int j, uint32_t x, uint32_t y, uint32_t z) const {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

uint32_t SM3::GG(int j, uint32_t x, uint32_t y, uint32_t z) const {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
}

void SM3::update(const uint8_t* data, size_t len) {
    totalLen += len;
    buffer.insert(buffer.end(), data, data + len);

    // 每收到64字节就处理一块
    while (buffer.size() >= 64) {
        processBlock(buffer.data());
        buffer.erase(buffer.begin(), buffer.begin() + 64);
    }
}

void SM3::update(const std::vector<uint8_t>& data) {
    update(data.data(), data.size());
}

void SM3::update(const std::string& data) {
    update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}
void SM3::setIV(const uint32_t iv_[8]) {
    std::memcpy(this->V, iv_, sizeof(this->V));
}
void SM3::setTotalLen(uint64_t len) {
    this->totalLen = len;
}
void SM3::pad() {
    size_t len = buffer.size();
    buffer.push_back(0x80); // 先添加1位1
    while ((buffer.size() + 8) % 64 != 0) {
        buffer.push_back(0x00); // 补0
    }

    // 添加总长度的64位表示
    uint64_t bitLen = totalLen * 8;
    for (int i = 7; i >= 0; --i) {
        buffer.push_back(static_cast<uint8_t>((bitLen >> (i * 8)) & 0xFF));
    }

    // 处理填充块
    for (size_t i = 0; i < buffer.size(); i += 64) {
        processBlock(&buffer[i]);
    }
}

void SM3::finalize(uint8_t hash[32]) {
    if (!finalized) {
        pad();
        // 将最终哈希值写出（大端）
        for (int i = 0; i < 8; ++i) {
            hash[i * 4 + 0] = static_cast<uint8_t>((V[i] >> 24) & 0xFF);
            hash[i * 4 + 1] = static_cast<uint8_t>((V[i] >> 16) & 0xFF);
            hash[i * 4 + 2] = static_cast<uint8_t>((V[i] >> 8) & 0xFF);
            hash[i * 4 + 3] = static_cast<uint8_t>((V[i]) & 0xFF);
        }
        finalized = true;
    }
}

std::vector<uint8_t> SM3::digest() {
    uint8_t hash[32];
    finalize(hash);
    return std::vector<uint8_t>(hash, hash + 32);
}

void SM3::processBlock(const uint8_t block[64]) {
    uint32_t W[68];  // 扩展消息字
    uint32_t W1[64]; // W′

    // 将输入消息分组转换为 W[0..15]
    for (int i = 0; i < 16; ++i) {
        W[i] = (block[i * 4 + 0] << 24) |
            (block[i * 4 + 1] << 16) |
            (block[i * 4 + 2] << 8) |
            (block[i * 4 + 3]);
    }

    // 消息扩展：W[16..67]
    for (int i = 16; i < 68; ++i) {
        uint32_t tmp = P1(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15));
        W[i] = tmp ^ ROTL(W[i - 13], 7) ^ W[i - 6];
    }

    // W′ = W[j] ^ W[j+4]
    for (int i = 0; i < 64; ++i) {
        W1[i] = W[i] ^ W[i + 4];
    }

    // 初始化寄存器值
    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    // 主循环：64轮
    for (int j = 0; j < 64; ++j) {
        uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T(j), j)) & 0xFFFFFFFF, 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);
        uint32_t TT1 = (FF(j, A, B, C) + D + SS2 + W1[j]) & 0xFFFFFFFF;
        uint32_t TT2 = (GG(j, E, F, G) + H + SS1 + W[j]) & 0xFFFFFFFF;

        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;

        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 更新中间杂凑值
    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}
