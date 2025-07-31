#pragma once

#include "sm4.h"
#include <immintrin.h> // AVX2

// 用 AVX2 模拟 VPROLD 优化的 L 变换
__m128i sm4_L_vprold(__m128i x);

class sm4_vprold : public sm4 {
public:
    sm4_vprold() = default;

    // 重写L函数，使用AVX2模拟VPROLD指令
    uint32_t L(uint32_t x) override;
};
