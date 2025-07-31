#include "sm4_vprold.h"

// AVX2实现的L变换，等价于 L(x) = x ^ (x rol 2) ^ (x rol 10) ^ (x rol 18) ^ (x rol 24)
__m128i sm4_L_vprold(__m128i x) {
    __m128i rol2 = _mm_or_si128(_mm_slli_epi32(x, 2), _mm_srli_epi32(x, 32 - 2));
    __m128i rol10 = _mm_or_si128(_mm_slli_epi32(x, 10), _mm_srli_epi32(x, 32 - 10));
    __m128i rol18 = _mm_or_si128(_mm_slli_epi32(x, 18), _mm_srli_epi32(x, 32 - 18));
    __m128i rol24 = _mm_or_si128(_mm_slli_epi32(x, 24), _mm_srli_epi32(x, 32 - 24));

    __m128i res = _mm_xor_si128(x, rol2);
    res = _mm_xor_si128(res, rol10);
    res = _mm_xor_si128(res, rol18);
    res = _mm_xor_si128(res, rol24);

    return res;
}

uint32_t sm4_vprold::L(uint32_t x) {
    __m128i val = _mm_cvtsi32_si128(x);  // 低32位装入128位寄存器
    __m128i res = sm4_L_vprold(val);
    return _mm_cvtsi128_si32(res);       // 取最低32位结果
}
