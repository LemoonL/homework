#ifndef SM3_H
#define SM3_H

#include <cstdint>
#include <vector>
#include <string>

class SM3 {
public:
    SM3(); 

    // 更新哈希数据 可以多次调用处理长数据
    void update(const uint8_t* data, size_t len);
    void update(const std::vector<uint8_t>& data);
    void update(const std::string& data);

    // 计算最终哈希结果
    void finalize(uint8_t hash[32]);
    std::vector<uint8_t> digest(); // 返回 std::vector 形式的 hash 值

private:
    // 处理一个 512 位（64 字节）消息块
    void processBlock(const uint8_t block[64]);

    // 填充数据并调用 processBlock
    void pad();

    void reset();

    uint32_t T(int j) const;

    uint32_t FF(int j, uint32_t x, uint32_t y, uint32_t z) const;
    uint32_t GG(int j, uint32_t x, uint32_t y, uint32_t z) const;

    uint32_t P0(uint32_t x) const;
    uint32_t P1(uint32_t x) const;

    // 左循环移位
    uint32_t ROTL(uint32_t x, int n) const;

    std::vector<uint8_t> buffer;  // 数据缓冲区
    uint64_t totalLen;            // 总消息长度
    uint32_t V[8];                // 中间哈希值（最终输出为 V0~V7）
    bool finalized;              // 是否已完成计算
};

#endif // SM3_H
