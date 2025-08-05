#include "sm3.h"       // 原始 SM3 类
#include "sm3_simd.h"  // SIMD 优化类
#include <chrono>
#include <iostream>
#include <iomanip>
#include <string>

void printHash(const std::vector<uint8_t>& hash) {
    for (auto b : hash)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    std::cout << "\n";
}

int main() {
    std::string message(1024 * 1024, 'A'); // 1MB 数据

    // 测试原始 SM3
    SM3 sm3;
    auto t1 = std::chrono::high_resolution_clock::now();
    sm3.update(reinterpret_cast<const uint8_t*>(message.data()), message.size());
    auto result1 = sm3.digest();
    auto t2 = std::chrono::high_resolution_clock::now();

    std::cout << "[原始SM3] time: " << std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count() << "ms\n";
    // 测试 SIMD SM3
    SM3_SIMD sm3simd;
    auto t3 = std::chrono::high_resolution_clock::now();
    sm3simd.update(reinterpret_cast<const uint8_t*>(message.data()), message.size());
    auto result2 = sm3simd.digest();
    auto t4 = std::chrono::high_resolution_clock::now();


    std::cout << "[SIMD SM3] time: " << std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t3).count() << "ms\n";
    std::cout << "[原始SM3]  hash: "; printHash(result1);
    std::cout << "[SIMD SM3] hash: "; printHash(result2);
    return 0;
}