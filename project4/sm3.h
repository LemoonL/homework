#ifndef SM3_H
#define SM3_H

#include <cstdint>
#include <vector>
#include <string>

class SM3 {
public:
    SM3(); 

    // ���¹�ϣ���� ���Զ�ε��ô�������
    void update(const uint8_t* data, size_t len);
    void update(const std::vector<uint8_t>& data);
    void update(const std::string& data);

    // �������չ�ϣ���
    void finalize(uint8_t hash[32]);
    std::vector<uint8_t> digest(); // ���� std::vector ��ʽ�� hash ֵ

private:
    // ����һ�� 512 λ��64 �ֽڣ���Ϣ��
    void processBlock(const uint8_t block[64]);

    // ������ݲ����� processBlock
    void pad();

    void reset();

    uint32_t T(int j) const;

    uint32_t FF(int j, uint32_t x, uint32_t y, uint32_t z) const;
    uint32_t GG(int j, uint32_t x, uint32_t y, uint32_t z) const;

    uint32_t P0(uint32_t x) const;
    uint32_t P1(uint32_t x) const;

    // ��ѭ����λ
    uint32_t ROTL(uint32_t x, int n) const;

    std::vector<uint8_t> buffer;  // ���ݻ�����
    uint64_t totalLen;            // ����Ϣ����
    uint32_t V[8];                // �м��ϣֵ���������Ϊ V0~V7��
    bool finalized;              // �Ƿ�����ɼ���
};

#endif // SM3_H
