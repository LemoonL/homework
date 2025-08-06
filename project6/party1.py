import random
from crypto_utils import hash_to_point, order
from ecdsa import ellipticcurve


def point_to_bytes(pt: ellipticcurve.Point):
    return (int(pt.x()).to_bytes(32, 'big') + int(pt.y()).to_bytes(32, 'big'))

# Party1 类，模拟第一方的行为
class Party1:
    def __init__(self, V, ahe):
        # 初始化 ID 列表和加法同态加密对象
        self.V = V
        self.ahe = ahe
        # 随机生成私钥 k1
        self.k1 = random.randint(1, order - 1)
        self.ahe = ahe
    def round1_send(self):
        # 计算每个 ID 的哈希值并乘以 k1
        self.Hv_k1 = [self.k1 * hash_to_point(v) for v in self.V]
        # 打乱顺序以保护隐私
        random.shuffle(self.Hv_k1)
        return self.Hv_k1

    def round3_process(self, Z, encrypted_pairs):
        # 将 Z 转换为集合以加速查找
        Z_bytes = {point_to_bytes(p) for p in Z}
        # 初始化加密和为 0
        ct_sum = None
        for Hw_k2, enc_t in encrypted_pairs:
            # 计算 k1 * k2 * H(w)
            Hwk1k2 = self.k1 * Hw_k2
            # 如果点在 Z 中，则累加对应的加密值
            if point_to_bytes(Hwk1k2) in Z_bytes:
                ct_sum = enc_t if ct_sum is None else ct_sum + enc_t
        return self.ahe.decrypt(ct_sum) if ct_sum else 0
