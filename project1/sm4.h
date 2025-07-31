#pragma once

#ifndef SM4_H
#define SM4_H

#include <cstdint>

class sm4 {
public:
    sm4();
    void setKey(const uint8_t key[16]);
    void encryptBlock(const uint8_t in[16], uint8_t out[16]);
    void decryptBlock(const uint8_t in[16], uint8_t out[16]);

private:
    uint32_t rk[32]; // round keys

    uint32_t F(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk);
    uint32_t T(uint32_t x);
    virtual uint32_t L(uint32_t x);
    uint32_t tau(uint32_t x);

    static uint8_t Sbox[256];
    static const uint32_t FK[4];
    static const uint32_t CK[32];
};

#endif
