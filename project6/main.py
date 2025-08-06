from crypto_utils import AHE
from party1 import Party1
from party2 import Party2

# 模拟交互
def main():
    # Party1 的 ID 列表
    V = ["aaa", "bbb", "ccc"]
    # Party2 的 ID-值对
    W = [("aaa", 10), ("ccc", 20), ("ddd", 30)]

    # 初始化加法同态加密（AHE）
    ahe = AHE()
    # 初始化 Party1 和 Party2
    p1 = Party1(V, ahe)
    p2 = Party2(W, ahe)

    # Round 1: Party1 发送加密的哈希值
    Hv_k1 = p1.round1_send()
    # Round 2: Party2 处理接收到的值并返回加密对
    Z, enc_pairs = p2.round2_process(Hv_k1)
    # Round 3: Party1 处理交集并返回加密和
    result = p1.round3_process(Z, enc_pairs)

    # 输出交集加和结果
    print("交集加和结果：", result)

if __name__ == "__main__":
    main()