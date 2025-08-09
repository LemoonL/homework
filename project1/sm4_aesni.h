#pragma once
#ifndef SM4_AESNI_H
#define SM4_AESNI_H

#include "sm4.h"
#include <immintrin.h>
#include <cstring>

class sm4_aesni : public sm4 {
public:
    sm4_aesni() = default;

    // ��д������ܣ�������8��ģ�ⵥ�����
    void encryptBlock(const uint8_t in[16], uint8_t out[16]) ;

    // ��д������ܣ�������8��ģ�ⵥ�����
    void decryptBlock(const uint8_t in[16], uint8_t out[16]) ;

    // ����8����ܽӿڣ�in/out��Ϊ128�ֽڻ�����
    void encryptBlocks8(const uint8_t* plaintext, uint8_t* ciphertext);

    // ����8����ܽӿ�
    void decryptBlocks8(const uint8_t* ciphertext, uint8_t* plaintext);

private:
    // �ڲ���̬��������������/���ܺ��ĺ���
    static void SM4_AESNI_do(uint8_t* in, uint8_t* out, const uint32_t* rk, int enc);

    static __m128i SM4_SBox(__m128i x);

    // �����Ǹ����궨��
#define MM_PACK0_EPI32(a, b, c, d) \
        _mm_unpacklo_epi64(_mm_unpacklo_epi32(a, b), _mm_unpacklo_epi32(c, d))
#define MM_PACK1_EPI32(a, b, c, d) \
        _mm_unpackhi_epi64(_mm_unpacklo_epi32(a, b), _mm_unpacklo_epi32(c, d))
#define MM_PACK2_EPI32(a, b, c, d) \
        _mm_unpacklo_epi64(_mm_unpackhi_epi32(a, b), _mm_unpackhi_epi32(c, d))
#define MM_PACK3_EPI32(a, b, c, d) \
        _mm_unpackhi_epi64(_mm_unpackhi_epi32(a, b), _mm_unpackhi_epi32(c, d))

#define MM_XOR2(a, b) _mm_xor_si128(a, b)
#define MM_XOR3(a, b, c) MM_XOR2(a, MM_XOR2(b, c))
#define MM_XOR4(a, b, c, d) MM_XOR2(a, MM_XOR3(b, c, d))
#define MM_XOR5(a, b, c, d, e) MM_XOR2(a, MM_XOR4(b, c, d, e))
#define MM_XOR6(a, b, c, d, e, f) MM_XOR2(a, MM_XOR5(b, c, d, e, f))
#define MM_ROTL_EPI32(a, n) \
        MM_XOR2(_mm_slli_epi32(a, n), _mm_srli_epi32(a, 32 - n))

    static __m128i MulMatrix(__m128i x, __m128i higherMask, __m128i lowerMask);
    static __m128i MulMatrixATA(__m128i x);
    static __m128i MulMatrixTA(__m128i x);
    static __m128i AddTC(__m128i x);
    static __m128i AddATAC(__m128i x);
};

#endif
