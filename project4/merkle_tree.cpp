#include "merkle_tree.h"
#include "sm3.h"
#include <algorithm>

static std::vector<uint8_t> hashLeaf(const std::string& data) {
    std::vector<uint8_t> input(data.begin(), data.end());
    input.insert(input.begin(), 0x00);  // Leaf prefix
    SM3 h;
    h.update(input.data(), input.size());
    return h.digest();
}

static std::vector<uint8_t> hashNode(const std::vector<uint8_t>& left,
    const std::vector<uint8_t>& right) {
    std::vector<uint8_t> input = { 0x01 };
    input.insert(input.end(), left.begin(), left.end());
    input.insert(input.end(), right.begin(), right.end());
    SM3 h;
    h.update(input.data(), input.size());
    return h.digest();
}

MerkleTree::MerkleTree(const std::vector<std::string>& leavesData) {
    std::vector<std::vector<uint8_t>> level;
    for (const auto& leaf : leavesData)
        level.push_back(hashLeaf(leaf));
    tree.push_back(level);

    while (tree.back().size() > 1) {
        const auto& prev = tree.back();
        std::vector<std::vector<uint8_t>> next;
        for (size_t i = 0; i < prev.size(); i += 2) {
            if (i + 1 < prev.size())
                next.push_back(hashNode(prev[i], prev[i + 1]));
            else
                next.push_back(prev[i]);  // Odd node promoted
        }
        tree.push_back(next);
    }
}

std::vector<uint8_t> MerkleTree::getRoot() const {
    return tree.back().front();
}

std::vector<std::vector<uint8_t>> MerkleTree::getInclusionProof(size_t leafIndex) const {
    std::vector<std::vector<uint8_t>> proof;
    size_t index = leafIndex;

    for (size_t level = 0; level < tree.size() - 1; ++level) {
        const auto& nodes = tree[level];
        size_t sibling = index ^ 1;
        if (sibling < nodes.size())
            proof.push_back(nodes[sibling]);
        index /= 2;
    }
    return proof;
}

bool MerkleTree::verifyInclusionProof(const std::string& leafData, size_t leafIndex,
    const std::vector<std::vector<uint8_t>>& proof,
    const std::vector<uint8_t>& expectedRoot) const {
    std::vector<uint8_t> hash = hashLeaf(leafData);
    size_t index = leafIndex;

    for (const auto& sibling : proof) {
        if (index % 2 == 0)
            hash = hashNode(hash, sibling);
        else
            hash = hashNode(sibling, hash);
        index /= 2;
    }
    return hash == expectedRoot;
}

bool MerkleTree::getNonInclusionProof(const std::string& leafData,
    std::vector<uint8_t>& closestLeafHashLeft,
    std::vector<uint8_t>& closestLeafHashRight) const {
    std::string target = leafData;
    std::vector<std::pair<std::string, std::vector<uint8_t>>> leafHashPairs;

    for (const auto& leafNode : tree[0]) {
        SM3 h;
        std::vector<uint8_t> digest = leafNode;
        leafHashPairs.emplace_back(std::string(digest.begin(), digest.end()), digest);
    }

    std::sort(leafHashPairs.begin(), leafHashPairs.end());

    for (size_t i = 0; i < leafHashPairs.size(); ++i) {
        std::string val = leafHashPairs[i].first;
        if (target < val) {
            if (i > 0) closestLeafHashLeft = leafHashPairs[i - 1].second;
            closestLeafHashRight = leafHashPairs[i].second;
            return true;
        }
    }
    return false;
}
