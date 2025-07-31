#pragma once

#include "sm4.h"
#include <immintrin.h> // AVX2

// �� AVX2 ģ�� VPROLD �Ż��� L �任
__m128i sm4_L_vprold(__m128i x);

class sm4_vprold : public sm4 {
public:
    sm4_vprold() = default;

    // ��дL������ʹ��AVX2ģ��VPROLDָ��
    uint32_t L(uint32_t x) override;
};
