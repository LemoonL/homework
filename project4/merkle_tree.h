#pragma once
#include <vector>
#include <string>
#include <memory>
#include <cstdint>

class MerkleTree {
public:
    explicit MerkleTree(const std::vector<std::string>& leaves);

    std::vector<uint8_t> getRoot() const;
    std::vector<std::vector<uint8_t>> getInclusionProof(size_t leafIndex) const;
    bool verifyInclusionProof(const std::string& leafData, size_t leafIndex,
        const std::vector<std::vector<uint8_t>>& proof,
        const std::vector<uint8_t>& expectedRoot) const;

    // 对不存在的“叶子值”，通过排序后比对前后叶子节点进行位置定位
    bool getNonInclusionProof(const std::string& leafData,
        std::vector<uint8_t>& closestLeafHashLeft,
        std::vector<uint8_t>& closestLeafHashRight) const;

private:
    std::vector<std::vector<std::vector<uint8_t>>> tree; // tree[level][node]
};
