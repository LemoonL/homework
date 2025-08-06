#ifndef SM3_SIMD_H
#define SM3_SIMD_H

#include <vector>
#include <string>
#include <cstdint>

class SM3_SIMD {
public:
    SM3_SIMD();
    void reset();
    void update(const uint8_t* data, size_t len);
    void update(const std::vector<uint8_t>& data);
    void update(const std::string& data);
    void finalize(uint8_t hash[32]);
    std::vector<uint8_t> digest();

private:
    void processBlock(const uint8_t block[64]);
    void pad();

    uint32_t rotate_left(uint32_t x, int n) const;
    uint32_t FF(uint32_t X, uint32_t Y, uint32_t Z, int j) const;
    uint32_t GG(uint32_t X, uint32_t Y, uint32_t Z, int j) const;
    uint32_t P_0(uint32_t X) const;
    uint32_t P_1(uint32_t X) const;

    uint32_t T[64];
    uint32_t hash[8];
    std::vector<uint8_t> buffer;
    uint64_t totalLen;
    bool finalized;
};

#endif // SM3_SIMD_H
