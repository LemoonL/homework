import random
from crypto_utils import hash_to_point, order
from ecdsa import ellipticcurve


def point_to_bytes(pt: ellipticcurve.Point):
    return (int(pt.x()).to_bytes(32, 'big') + int(pt.y()).to_bytes(32, 'big'))

# Party2 类，模拟第二方的行为
class Party2:
    def __init__(self, W, ahe):
        self.W = W  # [(id, val)]
        self.k2 = random.randint(1, order - 1)
        self.ahe = ahe
    def round2_process(self, Hv_k1_list):
        # 计算 Z = k2 * Hv_k1
        Z = [self.k2 * pt for pt in Hv_k1_list]
        random.shuffle(Z)
        encrypted_pairs = [
            (self.k2 * hash_to_point(w), self.ahe.encrypt(t))
            for (w, t) in self.W
        ]
        # 打乱顺序以保护隐私
        random.shuffle(encrypted_pairs)
        return Z, encrypted_pairs