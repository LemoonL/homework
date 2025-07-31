#include "sm4.h"
#include "sm4_table.h"
#include "sm4gcm.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <thread>
#include <cstring>
#include "sm4_vprold.h"

void printBlock(const uint8_t block[16]) {
    for (int i = 0; i < 16; ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)block[i] << " ";
    std::cout << std::dec << std::endl;
}

void encryptDecryptOrigSingle(sm4& cipher, const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    size_t numBlocks = in.size() / 16;
    std::vector<uint8_t> tmp(in.size());
    for (size_t i = 0; i < numBlocks; ++i) {
        cipher.encryptBlock(&in[i * 16], &tmp[i * 16]);
    }
    for (size_t i = 0; i < numBlocks; ++i) {
        cipher.decryptBlock(&tmp[i * 16], &out[i * 16]);
    }
}

void encryptDecryptTableSingle(sm4_table& cipher, const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    size_t numBlocks = in.size() / 16;
    std::vector<uint8_t> tmp(in.size());
    for (size_t i = 0; i < numBlocks; ++i) {
        cipher.encryptBlock(&in[i * 16], &tmp[i * 16]);
    }
    for (size_t i = 0; i < numBlocks; ++i) {
        cipher.decryptBlock(&tmp[i * 16], &out[i * 16]);
    }
}

void encryptDecryptOrigMulti(sm4& cipher, const std::vector<uint8_t>& in, std::vector<uint8_t>& out, size_t numThreads) {
    size_t numBlocks = in.size() / 16;
    size_t blocksPerThread = numBlocks / numThreads;
    std::vector<uint8_t> tmp(in.size());
    std::vector<std::thread> threads;

    for (size_t t = 0; t < numThreads; ++t) {
        size_t start = t * blocksPerThread;
        size_t end = (t == numThreads - 1) ? numBlocks : start + blocksPerThread;
        threads.emplace_back([&cipher, &in, &tmp, start, end]() {
            for (size_t i = start; i < end; ++i)
                cipher.encryptBlock(&in[i * 16], &tmp[i * 16]);
            });
    }
    for (auto& th : threads) th.join();

    threads.clear();
    for (size_t t = 0; t < numThreads; ++t) {
        size_t start = t * blocksPerThread;
        size_t end = (t == numThreads - 1) ? numBlocks : start + blocksPerThread;
        threads.emplace_back([&cipher, &tmp, &out, start, end]() {
            for (size_t i = start; i < end; ++i)
                cipher.decryptBlock(&tmp[i * 16], &out[i * 16]);
            });
    }
    for (auto& th : threads) th.join();
}

void encryptDecryptTableMulti(sm4_table& cipher, const std::vector<uint8_t>& in, std::vector<uint8_t>& out, size_t numThreads) {
    size_t numBlocks = in.size() / 16;
    size_t blocksPerThread = numBlocks / numThreads;
    std::vector<uint8_t> tmp(in.size());
    std::vector<std::thread> threads;

    for (size_t t = 0; t < numThreads; ++t) {
        size_t start = t * blocksPerThread;
        size_t end = (t == numThreads - 1) ? numBlocks : start + blocksPerThread;
        threads.emplace_back([&cipher, &in, &tmp, start, end]() {
            for (size_t i = start; i < end; ++i)
                cipher.encryptBlock(&in[i * 16], &tmp[i * 16]);
            });
    }
    for (auto& th : threads) th.join();

    threads.clear();
    for (size_t t = 0; t < numThreads; ++t) {
        size_t start = t * blocksPerThread;
        size_t end = (t == numThreads - 1) ? numBlocks : start + blocksPerThread;
        threads.emplace_back([&cipher, &tmp, &out, start, end]() {
            for (size_t i = start; i < end; ++i)
                cipher.decryptBlock(&tmp[i * 16], &out[i * 16]);
            });
    }
    for (auto& th : threads) th.join();
}

int main() {
    constexpr size_t NUM_BLOCKS = 100000;
    constexpr size_t NUM_THREADS = 8;

    uint8_t key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };

    std::vector<uint8_t> input(NUM_BLOCKS * 16);
    for (size_t i = 0; i < input.size(); ++i)
        input[i] = static_cast<uint8_t>(i);

    std::vector<uint8_t> out_orig_s(input.size()), out_table_s(input.size());
    std::vector<uint8_t> out_orig_mt(input.size()), out_table_mt(input.size());

    sm4 cipher_orig;
    sm4_table cipher_table;
    cipher_orig.setKey(key);
    cipher_table.setKey(key);

    auto t1 = std::chrono::high_resolution_clock::now();
    encryptDecryptOrigSingle(cipher_orig, input, out_orig_s);
    auto t2 = std::chrono::high_resolution_clock::now();

    encryptDecryptTableSingle(cipher_table, input, out_table_s);
    auto t3 = std::chrono::high_resolution_clock::now();

    encryptDecryptOrigMulti(cipher_orig, input, out_orig_mt, NUM_THREADS);
    auto t4 = std::chrono::high_resolution_clock::now();

    encryptDecryptTableMulti(cipher_table, input, out_table_mt, NUM_THREADS);
    auto t5 = std::chrono::high_resolution_clock::now();

    std::cout << "原始单线程时间: " << std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count() << " ms\n";
    std::cout << "查表单线程时间: " << std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count() << " ms\n";
    std::cout << "线程数 = " << NUM_THREADS << "\n";
    std::cout << "原始多线程时间: " << std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t3).count() << " ms\n";
    std::cout << "查表多线程时间: " << std::chrono::duration_cast<std::chrono::milliseconds>(t5 - t4).count() << " ms\n";

    std::cout << "\n验证结果:\n";
    std::cout << "原始单线程: " << (input == out_orig_s ? "正确" : "错误") << "\n";
    std::cout << "查表单线程: " << (input == out_table_s ? "正确" : "错误") << "\n";
    std::cout << "原始多线程: " << (input == out_orig_mt ? "正确" : "错误") << "\n";
    std::cout << "查表多线程: " << (input == out_table_mt ? "正确" : "错误") << "\n";

    sm4_vprold cipher_vprold;
    cipher_vprold.setKey(key);
    std::vector<uint8_t> out_vprold(input.size());

    auto t_vprold_start = std::chrono::high_resolution_clock::now();
    // 单线程加解密
    size_t numBlocks = input.size() / 16;
    std::vector<uint8_t> tmp_vprold(input.size());
    for (size_t i = 0; i < numBlocks; ++i)
        cipher_vprold.encryptBlock(&input[i * 16], &tmp_vprold[i * 16]);
    for (size_t i = 0; i < numBlocks; ++i)
        cipher_vprold.decryptBlock(&tmp_vprold[i * 16], &out_vprold[i * 16]);
    auto t_vprold_end = std::chrono::high_resolution_clock::now();
    std::cout << "VPROLD 验证结果: " << (input == out_vprold ? "正确" : "错误") << "\n";



    // SM4-GCM 测试
    std::cout << "\n========== SM4-GCM 测试 ==========" << std::endl;
    uint8_t iv[12] = { 0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac };
    uint8_t plaintext[32] = "This is a message to encrypt.";
    uint8_t ciphertext[32], decrypted[32], tag[16];

    sm4gcm gcm(key, iv, 12);
    gcm.encrypt(plaintext, 32, nullptr, 0, ciphertext, tag);

    std::cout << "明文:     "; printBlock(plaintext);
    std::cout << "密文:     "; printBlock(ciphertext);
    std::cout << "Tag:     "; printBlock(tag);

    bool ok = gcm.decrypt(ciphertext, 32, nullptr, 0, tag, decrypted);
    std::cout << "解密成功: " << (ok ? "是" : "否") << std::endl;
    if (ok) {
        std::cout << "解密后:   "; printBlock(decrypted);
    }

    return 0;
}
