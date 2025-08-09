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
#include"sm4_aesni.h"
#include "sm4_gcm_opt.h" 
#include"sm4_gcm_simd.h"


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

// ����AESNI���Ժ�������������
void encryptDecryptAESNI(sm4_aesni& cipher, const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    size_t numBlocks = in.size() / 16;
    size_t numBlocks8 = numBlocks / 8; // 8��һ��
    std::vector<uint8_t> tmp(in.size());

    for (size_t i = 0; i < numBlocks8; ++i) {
        cipher.encryptBlocks8(&in[i * 8 * 16], &tmp[i * 8 * 16]);
    }
    for (size_t i = 0; i < numBlocks8; ++i) {
        cipher.decryptBlocks8(&tmp[i * 8 * 16], &out[i * 8 * 16]);
    }

    // ��ʣ�಻��8�飬���Լ�����ͨ���麯���������ߺ���
    size_t remainder = numBlocks % 8;
    size_t offset = numBlocks8 * 8 * 16;
    for (size_t i = 0; i < remainder; ++i) {
        // ��ԭʼ����ӽ��������䣨���Լ�ʵ�ֵ���AESNI��
        cipher.encryptBlock(&in[offset + i * 16], &tmp[offset + i * 16]);
        cipher.decryptBlock(&tmp[offset + i * 16], &out[offset + i * 16]);
    }
}

// gcm test

//void print_hex16(const uint8_t b[16]) {
//    for (int i = 0; i < 16; ++i)
//        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b[i] << " ";
//    std::cout << std::dec << std::endl;
//}

//void diag_gmul_compare() {
//    uint8_t key[16] = {
//        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
//        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
//    };
//    uint8_t iv[12] = { 0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac };
//
//    // ѡһ������ X �� Y������ X = first plaintext block, Y = H��
//    uint8_t X[16] = { 0 };
//    uint8_t Y[16] = { 0 };
//
//    // �趨 X Ϊĳ�����Կ飨�������ĵĵ�һ���飩
//    const char* msg = "This is a message to encrypt.";
//    memcpy(X, msg, std::min<size_t>(16, strlen(msg)));
//
//    // ���� H ��ԭʼ/��һ�������õ�һ�µ� H��ʹ��ͬһ�� key/iv��
//    sm4gcm g1(key, iv, 12);
//    sm4_gcm_simd g2(key, iv, 12);
//
//    // ��ȡ H������Ӧ��ͬ��
//    uint8_t H1[16], H2[16];
//    memcpy(H1, g1.H, 16);   // ע�⣺��� H �� private����Ҫ�Ѳ��Ժ�������ͬһ�ļ���� H ��¶������
//    memcpy(H2, g2.H, 16);
//
//    std::cout << "H (orig): "; print_hex16(H1);
//    std::cout << "H (simd): "; print_hex16(H2);
//
//    // ���� X �� Y ��������ʵ��
//    uint8_t X_for_orig[16], X_for_simd[16];
//    memcpy(X_for_orig, X, 16);
//    memcpy(X_for_simd, X, 16);
//
//    // ���ø��Ե� gmul��X = X * H
//    g1.gmul(X_for_orig, H1);     // ��Ҫ gmul ����ɼ��������Է���ͬһԴ�ļ�
//    g2.gmul(X_for_simd, H2);
//
//    std::cout << "\nAfter gmul:\n";
//    std::cout << "orig X * H: "; print_hex16(X_for_orig);
//    std::cout << "simd X * H: "; print_hex16(X_for_simd);
//
//    // �����ͬ��������ӡ�м䣨���������gmul���ӡV, Z, ��simd���ӡ xr, yr, r��
//}


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
    sm4_aesni cipher_aesni;
    cipher_aesni.setKey(key);
    std::vector<uint8_t> out_aesni(input.size());

    auto t_aesni_start = std::chrono::high_resolution_clock::now();
    encryptDecryptAESNI(cipher_aesni, input, out_aesni);
    auto t_aesni_end = std::chrono::high_resolution_clock::now();
    
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

    std::cout << "ԭʼ���߳�ʱ��: " << std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count() << " ms\n";
    std::cout << "����߳�ʱ��: " << std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count() << " ms\n";
    std::cout << "�߳��� = " << NUM_THREADS << "\n";
    std::cout << "ԭʼ���߳�ʱ��: " << std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t3).count() << " ms\n";
    std::cout << "�����߳�ʱ��: " << std::chrono::duration_cast<std::chrono::milliseconds>(t5 - t4).count() << " ms\n";
    std::cout << "AES-NI �����ӽ���ʱ��: " << std::chrono::duration_cast<std::chrono::milliseconds>(t_aesni_end - t_aesni_start).count() << " ms\n";
    std::cout << "\n��֤���:\n";
    std::cout << "ԭʼ���߳�: " << (input == out_orig_s ? "��ȷ" : "����") << "\n";
    std::cout << "����߳�: " << (input == out_table_s ? "��ȷ" : "����") << "\n";
    std::cout << "ԭʼ���߳�: " << (input == out_orig_mt ? "��ȷ" : "����") << "\n";
    std::cout << "�����߳�: " << (input == out_table_mt ? "��ȷ" : "����") << "\n";
    std::cout << "AES-NI ��֤���: " << (input == out_aesni ? "��ȷ" : "����") << "\n";
    sm4_vprold cipher_vprold;
    cipher_vprold.setKey(key);
    std::vector<uint8_t> out_vprold(input.size());

    auto t_vprold_start = std::chrono::high_resolution_clock::now();
    // ���̼߳ӽ���
    size_t numBlocks = input.size() / 16;
    std::vector<uint8_t> tmp_vprold(input.size());
    for (size_t i = 0; i < numBlocks; ++i)
        cipher_vprold.encryptBlock(&input[i * 16], &tmp_vprold[i * 16]);
    for (size_t i = 0; i < numBlocks; ++i)
        cipher_vprold.decryptBlock(&tmp_vprold[i * 16], &out_vprold[i * 16]);
    auto t_vprold_end = std::chrono::high_resolution_clock::now();
    std::cout << "VPROLD ��֤���: " << (input == out_vprold ? "��ȷ" : "����") << "\n";



    // SM4-GCM ����
    std::cout << "\n========== SM4-GCM ���� ==========" << std::endl;
    uint8_t iv[12] = { 0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac };
    uint8_t plaintext[32] = "This is a message to encrypt.";
    uint8_t ciphertext[32], decrypted[32], tag[16];

    sm4gcm gcm(key, iv, 12);

    auto t_start_orig = std::chrono::high_resolution_clock::now();
    gcm.encrypt(plaintext, 32, nullptr, 0, ciphertext, tag);
    auto t_end_orig = std::chrono::high_resolution_clock::now();

    std::cout << "sm4gcm ԭʼ�汾:\n";
    std::cout << "����:     "; printBlock(plaintext);
    std::cout << "����:     "; printBlock(ciphertext);
    std::cout << "Tag:      "; printBlock(tag);

    bool ok = gcm.decrypt(ciphertext, 32, nullptr, 0, tag, decrypted);
    std::cout << "���ܳɹ�: " << (ok ? "��" : "��") << std::endl;
    if (ok) {
        std::cout << "���ܺ�:   "; printBlock(decrypted);
    }
    std::cout << "sm4gcm ���ܺ�ʱ: "
        << std::chrono::duration_cast<std::chrono::microseconds>(t_end_orig - t_start_orig).count()
        << " us\n";

    std::cout << "\n========== sm4_gcm_opt �Ż������ ==========" << std::endl;

    sm4_gcm_opt gcm_opt(key, iv, 12);
    uint8_t ciphertext_opt[32], decrypted_opt[32], tag_opt[16];

    auto t_start_opt = std::chrono::high_resolution_clock::now();
    gcm_opt.encrypt(plaintext, 32, nullptr, 0, ciphertext_opt, tag_opt);
    auto t_end_opt = std::chrono::high_resolution_clock::now();

    std::cout << "����:     "; printBlock(plaintext);
    std::cout << "����:     "; printBlock(ciphertext_opt);
    std::cout << "Tag:      "; printBlock(tag_opt);

    bool ok_opt = gcm_opt.decrypt(ciphertext_opt, 32, nullptr, 0, tag_opt, decrypted_opt);
    std::cout << "���ܳɹ�: " << (ok_opt ? "��" : "��") << std::endl;
    if (ok_opt) {
        std::cout << "���ܺ�:   "; printBlock(decrypted_opt);
    }

    std::cout << "sm4_gcm_opt ���ܺ�ʱ: "
        << std::chrono::duration_cast<std::chrono::microseconds>(t_end_opt - t_start_opt).count()
        << " us\n";
    std::cout << "\n========== sm4_gcm_simd �Ż������ ==========" << std::endl;

    // SIMD �汾����
    sm4_gcm_simd gcm_simd(key, iv, 12);
    uint8_t ciphertext_simd[32], decrypted_simd[32], tag_simd[16];
    auto t_start_simd = std::chrono::high_resolution_clock::now();
    gcm_simd.encrypt(plaintext, 32, nullptr, 0, ciphertext_simd, tag_simd);
    auto t_end_simd = std::chrono::high_resolution_clock::now();

    std::cout << "sm4_gcm_simd SIMD�汾:\n";
    std::cout << "����:     "; printBlock(plaintext);
    std::cout << "����:     "; printBlock(ciphertext_simd);
    std::cout << "Tag:      "; printBlock(tag_simd);

    bool ok_simd = gcm_simd.decrypt(ciphertext_simd, 32, nullptr, 0, tag_simd, decrypted_simd);
    std::cout << "���ܳɹ�: " << (ok_simd ? "��" : "��") << std::endl;
    if (ok_simd) std::cout << "���ܺ�:   "; printBlock(decrypted_simd);
    std::cout << "sm4_gcm_simd ���ܺ�ʱ: "
        << std::chrono::duration_cast<std::chrono::microseconds>(t_end_simd - t_start_simd).count()
        << " us\n\n";

    return 0;
}
