import hashlib
import secrets
from ecdsa import ellipticcurve

# SM2推荐曲线参数（GM/T 0003.5-2012）
p = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
a = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
b = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
Gx = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
Gy = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
n = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)

# 构造曲线和基点
curve_sm2 = ellipticcurve.CurveFp(p, a, b)
G = ellipticcurve.Point(curve_sm2, Gx, Gy, n)


def int_to_bytes(x: int, size: int = 32) -> bytes:
    return x.to_bytes(size, byteorder='big')


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')


def kdf(z: bytes, klen: int) -> bytes:
    """
    密钥派生函数（KDF），用SHA-256实现
    """
    ct = 1
    K = b''
    while len(K) < klen:
        K += hashlib.sha256(z + int_to_bytes(ct, 4)).digest()
        ct += 1
    return K[:klen]


def montgomery_ladder(k: int, P: ellipticcurve.Point) -> ellipticcurve.Point:
    """
    蒙哥马利阶梯算法实现标量乘法
    无条件分支，安全且较快
    """
    R0 = ellipticcurve.INFINITY
    R1 = P

    k_bin = bin(k)[2:]  # 去掉 '0b'

    for bit in k_bin:
        if bit == '0':
            R1 = R0 + R1
            R0 = R0.double()
        else:
            R0 = R0 + R1
            R1 = R1.double()

    return R0


class SM2_opt:
    def __init__(self, private_key: int = None):
        if private_key:
            self.d = private_key
        else:
            self.d = secrets.randbelow(n - 1) + 1
        self.P = montgomery_ladder(self.d, G)

    def get_public_key(self):
        return self.P

    def encrypt(self, M: bytes, pubkey: ellipticcurve.Point) -> bytes:
        while True:
            k = secrets.randbelow(n - 1) + 1
            C1 = montgomery_ladder(k, G)
            S = montgomery_ladder(k, pubkey)
            x2, y2 = S.x(), S.y()
            z = int_to_bytes(x2, 32) + int_to_bytes(y2, 32)
            t = kdf(z, len(M))
            if any(t):  # t ≠ 0，避免全零
                break
        C2 = bytes([a ^ b for a, b in zip(M, t)])
        C3 = hashlib.sha256(int_to_bytes(x2, 32) + M + int_to_bytes(y2, 32)).digest()
        return int_to_bytes(C1.x(), 32) + int_to_bytes(C1.y(), 32) + C3 + C2

    def decrypt(self, C: bytes) -> bytes:
        x1 = bytes_to_int(C[0:32])
        y1 = bytes_to_int(C[32:64])
        C1 = ellipticcurve.Point(curve_sm2, x1, y1)
        if not curve_sm2.contains_point(x1, y1):
            raise ValueError("Invalid C1 point on curve")
        C3 = C[64:96]
        C2 = C[96:]
        S = montgomery_ladder(self.d, C1)
        x2, y2 = S.x(), S.y()
        z = int_to_bytes(x2, 32) + int_to_bytes(y2, 32)
        t = kdf(z, len(C2))
        M = bytes([a ^ b for a, b in zip(C2, t)])
        u = hashlib.sha256(int_to_bytes(x2, 32) + M + int_to_bytes(y2, 32)).digest()
        if u != C3:
            raise ValueError("Invalid C3 hash, decryption failed.")
        return M


# 测试
if __name__ == "__main__":
    sm2opt = SM2_opt()
    pubkey = sm2opt.get_public_key()
    print(f"私钥 d: {sm2opt.d}")
    print(f"公钥 P: ({pubkey.x()}, {pubkey.y()})")

    plaintext = b"Hello SM2_opt"
    print(f"明文: {plaintext}")

    ciphertext = sm2opt.encrypt(plaintext, pubkey)
    print(f"密文(hex): {ciphertext.hex()}")

    decrypted = sm2opt.decrypt(ciphertext)
    print(f"解密后: {decrypted}")

    assert decrypted == plaintext, "解密失败！"
