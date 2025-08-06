#include "sm3.h"       // 原始 SM3 类
#include "sm3_simd.h"  // SIMD 优化类
#include "merkle_tree.h"
#include <chrono>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <vector>
#include <random>
void printHash(const std::vector<uint8_t>& hash) {
    for (auto b : hash)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    std::cout << "\n";
}

// SM3 填充函数
std::vector<uint8_t> sm3_padding(size_t original_len) {
    uint64_t bit_len = original_len * 8;
    std::vector<uint8_t> pad;

    pad.push_back(0x80);
    while ((original_len + pad.size() + 8) % 64 != 0) {
        pad.push_back(0x00);
    }

    for (int i = 7; i >= 0; --i) {
        pad.push_back((bit_len >> (i * 8)) & 0xFF);
    }
    return pad;
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

    std::cout << "\n========== SM3 length-extension attack  ==========" << std::endl;

    // 原始消息 m1 和扩展消息 m2
    std::string m1 = "hello";
    std::string m2 = "world";

    // 1. 获取原始 m1 的 hash 值（h1）
    SM3 sm3_att;
    sm3_att.update(reinterpret_cast<const uint8_t*>(m1.data()), m1.size());
    std::vector<uint8_t> h1 = sm3_att.digest();

    std::cout << "[原始消息] hash(m1): ";
    printHash(h1);

    // 2. 构造伪造消息 m1 || pad(m1) || m2
    std::vector<uint8_t> forged_message(m1.begin(), m1.end());
    std::vector<uint8_t> pad = sm3_padding(m1.size());
    forged_message.insert(forged_message.end(), pad.begin(), pad.end());
    forged_message.insert(forged_message.end(), m2.begin(), m2.end());

    // 3. 设置 IV 为 h1，继续 hash(m2)，模拟扩展攻击
    SM3 attacker;
    uint32_t iv[8];
    for (int i = 0; i < 8; ++i) {
        iv[i] = (h1[i * 4 + 0] << 24) | (h1[i * 4 + 1] << 16) |
            (h1[i * 4 + 2] << 8) | (h1[i * 4 + 3]);
    }
    attacker.setIV(iv);
    attacker.setTotalLen(m1.size() + pad.size()); // 伪造的 "原始消息长度"
    attacker.update(reinterpret_cast<const uint8_t*>(m2.data()), m2.size());
    std::vector<uint8_t> forged_hash = attacker.digest();

    std::cout << "[伪造消息] hash(m1||pad||m2): ";
    printHash(forged_hash);

    // 4. 验证 forged_message 的真实 hash 是否相同
    SM3 verify;
    verify.update(forged_message);
    std::vector<uint8_t> verify_hash = verify.digest();

    std::cout << "[验证消息] hash(forged_message): ";
    printHash(verify_hash);

    if (verify_hash == forged_hash) {
        std::cout << "\n 攻击成功！伪造 hash 与真实 hash 相同，攻击成立！\n";
    }
    else {
        std::cout << "\n 攻击失败....伪造 hash 与真实 hash 不一致！\n";
    }
    std::cout << "\n========== Merkle tree  ==========" << std::endl;
    std::vector<std::string> leaves;
    for (int i = 0; i < 100000; ++i)
        leaves.push_back("leaf_" + std::to_string(i));

    MerkleTree tree(leaves);
    auto root = tree.getRoot();

    std::cout << "Merkle Root: ";
    for (auto b : root) std::cout << std::hex << (int)b;
    std::cout << "\n";

    // 存在性证明
    size_t targetIndex = 12345;
    auto proof = tree.getInclusionProof(targetIndex);
    bool verified = tree.verifyInclusionProof(leaves[targetIndex], targetIndex, proof, root);
    std::cout << "Inclusion proof verified: " << (verified ? "yes" : "no") << "\n";

    // 不存在性证明
    std::string fakeLeaf = "leaf_100001";
    std::vector<uint8_t> left, right;
    if (tree.getNonInclusionProof(fakeLeaf, left, right)) {
        std::cout << "Non-inclusion proof shows between:\n";
        for (auto b : left) std::cout << std::hex << (int)b;
        std::cout << " < " << fakeLeaf << " < ";
        for (auto b : right) std::cout << std::hex << (int)b;
        std::cout << "\n";
    }

    return 0;
}
