#include "sm4_aesni.h"

// 单块加密模拟批量8块加密
void sm4_aesni::encryptBlock(const uint8_t in[16], uint8_t out[16]) {
    alignas(16) uint8_t in8[128] = { 0 };
    alignas(16) uint8_t out8[128] = { 0 };
    std::memcpy(in8, in, 16);
    SM4_AESNI_do(in8, out8, rk, 0);
    std::memcpy(out, out8, 16);
}

// 单块解密模拟批量8块解密
void sm4_aesni::decryptBlock(const uint8_t in[16], uint8_t out[16]) {
    alignas(16) uint8_t in8[128] = { 0 };
    alignas(16) uint8_t out8[128] = { 0 };
    std::memcpy(in8, in, 16);
    SM4_AESNI_do(in8, out8, rk, 1);
    std::memcpy(out, out8, 16);
}



void sm4_aesni::encryptBlocks8(const uint8_t* plaintext, uint8_t* ciphertext) {
    SM4_AESNI_do(const_cast<uint8_t*> (plaintext), ciphertext, rk, 0);
    SM4_AESNI_do(const_cast<uint8_t*> (plaintext + 64), ciphertext + 64, rk, 0); // 处理后4块（64字节偏移）
}

void sm4_aesni::decryptBlocks8(const uint8_t* ciphertext, uint8_t* plaintext) {
    SM4_AESNI_do(const_cast<uint8_t*> (ciphertext), plaintext, rk, 1);
    SM4_AESNI_do(const_cast<uint8_t*>(ciphertext + 64), plaintext + 64, rk, 1); // 处理后4块（64字节偏移）
}

// 核心批量加解密函数
void sm4_aesni::SM4_AESNI_do(uint8_t* in, uint8_t* out, const uint32_t* rk, int enc) {
    __m128i X[4], Tmp[4];
    __m128i vindex = _mm_setr_epi8(
        3, 2, 1, 0,
        7, 6, 5, 4,
        11, 10, 9, 8,
        15, 14, 13, 12);

    // Load 4 * 128bit blocks = 512 bytes ? No, 4*16 bytes = 64 bytes, so loading 4 __m128i from input + 4 more blocks from in+16, +32, +48...
    Tmp[0] = _mm_loadu_si128((const __m128i*)in + 0);
    Tmp[1] = _mm_loadu_si128((const __m128i*)in + 1);
    Tmp[2] = _mm_loadu_si128((const __m128i*)in + 2);
    Tmp[3] = _mm_loadu_si128((const __m128i*)in + 3);

    X[0] = MM_PACK0_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    X[1] = MM_PACK1_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    X[2] = MM_PACK2_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    X[3] = MM_PACK3_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);

    // Shuffle endianess
    X[0] = _mm_shuffle_epi8(X[0], vindex);
    X[1] = _mm_shuffle_epi8(X[1], vindex);
    X[2] = _mm_shuffle_epi8(X[2], vindex);
    X[3] = _mm_shuffle_epi8(X[3], vindex);

    for (int i = 0; i < 32; i++) {
        __m128i k = _mm_set1_epi32(enc == 0 ? rk[i] : rk[31 - i]);
        Tmp[0] = MM_XOR4(X[1], X[2], X[3], k);
        Tmp[0] = SM4_SBox(Tmp[0]);
        Tmp[0] = MM_XOR6(X[0], Tmp[0],
            MM_ROTL_EPI32(Tmp[0], 2),
            MM_ROTL_EPI32(Tmp[0], 10),
            MM_ROTL_EPI32(Tmp[0], 18),
            MM_ROTL_EPI32(Tmp[0], 24));
        X[0] = X[1]; X[1] = X[2]; X[2] = X[3]; X[3] = Tmp[0];
    }

    X[0] = _mm_shuffle_epi8(X[0], vindex);
    X[1] = _mm_shuffle_epi8(X[1], vindex);
    X[2] = _mm_shuffle_epi8(X[2], vindex);
    X[3] = _mm_shuffle_epi8(X[3], vindex);

    _mm_storeu_si128((__m128i*)out + 0, MM_PACK0_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)out + 1, MM_PACK1_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)out + 2, MM_PACK2_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)out + 3, MM_PACK3_EPI32(X[3], X[2], X[1], X[0]));
}

__m128i sm4_aesni::MulMatrix(__m128i x, __m128i higherMask, __m128i lowerMask) {
    __m128i tmp1, tmp2;
    __m128i andMask = _mm_set1_epi32(0x0f0f0f0f);
    tmp2 = _mm_srli_epi16(x, 4);
    tmp1 = _mm_and_si128(x, andMask);
    tmp2 = _mm_and_si128(tmp2, andMask);
    tmp1 = _mm_shuffle_epi8(lowerMask, tmp1);
    tmp2 = _mm_shuffle_epi8(higherMask, tmp2);
    tmp1 = _mm_xor_si128(tmp1, tmp2);
    return tmp1;
}

__m128i sm4_aesni::MulMatrixATA(__m128i x) {
    __m128i higherMask = _mm_set_epi8(
        0x14, 0x07, (char)0xc6, (char)0xd5, 0x6c, 0x7f, (char)0xbe, (char)0xad,
        (char)0xb9, (char)0xaa, 0x6b, 0x78, (char)0xc1, (char)0xd2, 0x13, 0x00);

    __m128i lowerMask = _mm_set_epi8(
        (char)0xd8, (char)0xb8, (char)0xfa, (char)0x9a, (char)0xc5, (char)0xa5, (char)0xe7, (char)0x87,
        0x5f, 0x3f, 0x7d, 0x1d, 0x42, 0x22, 0x60, 0x00);

    return MulMatrix(x, higherMask, lowerMask);
}


__m128i sm4_aesni::MulMatrixTA(__m128i x) {
    __m128i higherMask = _mm_set_epi8(
        0x22, 0x58, 0x1a, 0x60, 0x02, 0x78, 0x3a, 0x40,
        0x62, 0x18, 0x5a, 0x20, 0x42, 0x38, 0x7a, 0x00);

    __m128i lowerMask = _mm_set_epi8(
        (char)0xe2, 0x28, (char)0x95, 0x5f, 0x69, (char)0xa3, 0x1e, (char)0xd4,
        0x36, (char)0xfc, 0x41, (char)0x8b, (char)0xbd, 0x77, (char)0xca, 0x00);

    return MulMatrix(x, higherMask, lowerMask);
}

__m128i sm4_aesni::AddTC(__m128i x) {
    __m128i TC = _mm_set1_epi8(0b00100011);
    return _mm_xor_si128(x, TC);
}

__m128i sm4_aesni::AddATAC(__m128i x) {
    __m128i ATAC = _mm_set1_epi8(0b00111011);
    return _mm_xor_si128(x, ATAC);
}

__m128i sm4_aesni::SM4_SBox(__m128i x) {
    __m128i MASK = _mm_set_epi8(
        0x03, 0x06, 0x09, 0x0c,
        0x0f, 0x02, 0x05, 0x08,
        0x0b, 0x0e, 0x01, 0x04,
        0x07, 0x0a, 0x0d, 0x00);
    x = _mm_shuffle_epi8(x, MASK);
    x = AddTC(MulMatrixTA(x));
    x = _mm_aesenclast_si128(x, _mm_setzero_si128());
    return AddATAC(MulMatrixATA(x));
}
