import hashlib
from ecdsa import ellipticcurve, numbertheory
from ecdsa.curves import NIST256p
import secrets
import time
# === SM2推荐椭圆曲线参数（来自国密标准） ===
p = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
a = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
b = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
Gx = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
Gy = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
n = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)

curve = ellipticcurve.CurveFp(p, a, b)
G = ellipticcurve.Point(curve, Gx, Gy, n)

# === 预计算窗口大小（可选值：2, 4, 8，越大速度越快，占用内存也更多）===
WINDOW_SIZE = 8

def int_to_bytes(x: int, size: int) -> bytes:
    return x.to_bytes(size, byteorder='big')

class SM2_window_opt:
    def __init__(self):
        self.private_key = secrets.randbelow(n - 1) + 1
        self.public_key = self.private_key * G
        self.precomputed_table = self._precompute_window_points(G)

    def _precompute_window_points(self, base_point):
        """预计算 G, 2G, ..., (2^w - 1)G"""
        table = {}
        for i in range(1, 2 ** WINDOW_SIZE):
            table[i] = i * base_point
        return table

    def _window_scalar_mult(self, k):
        """使用窗口法优化的标量乘法"""
        result = None
        k_bin = bin(k)[2:]
        i = 0
        while i < len(k_bin):
            if k_bin[i] == '0':
                result = result.double() if result else None
                i += 1
            else:
                win = k_bin[i:i + WINDOW_SIZE]
                win_val = int(win, 2)
                i += len(win)
                if result is None:
                    result = self.precomputed_table[win_val]
                else:
                    for _ in range(len(win)):
                        result = result.double()
                    result += self.precomputed_table[win_val]
        return result

    def encrypt(self, plaintext: str, use_window=True) -> bytes:
        m = plaintext.encode()
        while True:
            k = secrets.randbelow(n - 1) + 1
            C1 = self._window_scalar_mult(k) if use_window else k * G
            S = k * self.public_key
            x2, y2 = S.x(), S.y()
            t = hashlib.sha256((str(x2) + str(y2)).encode()).digest()
            if int.from_bytes(t, 'big') != 0:
                break
        C2 = bytes([m[i] ^ t[i] for i in range(len(m))])
        C3 = hashlib.sha256((str(x2) + plaintext + str(y2)).encode()).digest()
        return int_to_bytes(C1.x(), 32) + int_to_bytes(C1.y(), 32) + C3 + C2
        ##return (str(C1.x()) + "," + str(C1.y()) + "|" +
                ##C2.hex() + "|" + C3.hex()).encode()
                
    def decrypt(self, ciphertext: bytes) -> str:
        # 解析 C1
        x1 = int.from_bytes(ciphertext[0:32], byteorder='big')
        y1 = int.from_bytes(ciphertext[32:64], byteorder='big')
        C1 = ellipticcurve.Point(curve, x1, y1, n)

        # 解析 C3（哈希）和 C2（密文）
        C3 = ciphertext[64:96]
        C2 = ciphertext[96:]

        # 计算共享点 S = d * C1
        S = self.private_key * C1
        x2, y2 = S.x(), S.y()

        # 生成密钥 t
        t = hashlib.sha256((str(x2) + str(y2)).encode()).digest()
        if len(t) < len(C2):
            raise ValueError("派生密钥长度不足")

        # 解密 C2
        m = bytes([C2[i] ^ t[i] for i in range(len(C2))])

        # 验证 C3
        u = hashlib.sha256((str(x2) + m.decode() + str(y2)).encode()).digest()
        if u != C3:
            raise ValueError("解密失败，消息认证失败")

        return m.decode()

    def decrypt1(self, ciphertext: bytes) -> str:
        C1_str, C2_hex, C3_hex = ciphertext.decode().split("|")
        x1_str, y1_str = C1_str.split(",")
        C1 = ellipticcurve.Point(curve, int(x1_str), int(y1_str), n)
        S = self.private_key * C1
        x2, y2 = S.x(), S.y()
        t = hashlib.sha256((str(x2) + str(y2)).encode()).digest()
        C2 = bytes.fromhex(C2_hex)
        m = bytes([C2[i] ^ t[i] for i in range(len(C2))])
        u = hashlib.sha256((str(x2) + m.decode() + str(y2)).encode()).digest()
        if u.hex() != C3_hex:
            raise ValueError("解密失败，消息认证失败")
        return m.decode()
     
    def get_keys(self):
        return self.private_key, self.public_key
# 测试示例
if __name__ == "__main__":
    sm2 = SM2_window_opt()
    message = "project5"

    # 加密
    t1 = time.time()
    ciphertext = sm2.encrypt(message, use_window=True)
    t2 = time.time()
    print("[窗口法SM2] 密文(hex):", ciphertext.hex())
    print("加密用时:", round(t2 - t1, 6), "秒")

    # 解密
    t3 = time.time()
    plaintext = sm2.decrypt(ciphertext)
    t4 = time.time()
    print("解密明文:", plaintext)
    print("解密用时:", round(t4 - t3, 6), "秒")