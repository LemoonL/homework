import hashlib
import secrets
from ecdsa import ellipticcurve


# SM2 recommended curve parameters from GM/T 0003.5-2012
p = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
a = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
b = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
Gx = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
Gy = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
n = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)

# 构造 SM2 曲线和生成元
curve_sm2 = ellipticcurve.CurveFp(p, a, b)
G = ellipticcurve.Point(curve_sm2, Gx, Gy, n)

def int_to_bytes(x: int, size: int) -> bytes:
    return x.to_bytes(size, byteorder='big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def kdf(z: bytes, klen: int) -> bytes:
    """密钥派生函数（KDF），使用 SHA-256"""
    ct = 1
    K = b''
    while len(K) < klen:
        K += hashlib.sha256(z + int_to_bytes(ct, 4)).digest()
        ct += 1
    return K[:klen]

class SM2:
    def __init__(self, private_key: int = None):
        if private_key:
            self.d = private_key
        else:
            self.d = secrets.randbelow(n - 1) + 1
        self.P = self.d * G

    def get_public_key(self):
        return self.P

    def encrypt(self, M: bytes, pubkey: ellipticcurve.Point) -> bytes:
        while True:
            k = secrets.randbelow(n - 1) + 1
            C1 = k * G
            S = k * pubkey
            x2, y2 = S.x(), S.y()
            z = int_to_bytes(x2, 32) + int_to_bytes(y2, 32)
            t = kdf(z, len(M))
            if any(t):  # t ≠ 0
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
        S = self.d * C1
        x2, y2 = S.x(), S.y()
        z = int_to_bytes(x2, 32) + int_to_bytes(y2, 32)
        t = kdf(z, len(C2))
        M = bytes([a ^ b for a, b in zip(C2, t)])
        u = hashlib.sha256(int_to_bytes(x2, 32) + M + int_to_bytes(y2, 32)).digest()
        if u != C3:
            raise ValueError("Invalid C3 hash, decryption failed.")
        return M

    def sign(self, message: bytes) -> tuple:
        e = int.from_bytes(hashlib.sha256(message).digest(), 'big') % n
        while True:
            k = secrets.randbelow(n - 1) + 1
            P1 = k * G
            r = (e + P1.x()) % n
            if r == 0 or r + k == n:
                continue
            s = ((k - r * self.d) * pow(1 + self.d, -1, n)) % n
            if s != 0:
                break
        return r, s

    def verify(self, message: bytes, signature: tuple, pubkey: ellipticcurve.Point) -> bool:
        r, s = signature
        if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
            return False
        e = int.from_bytes(hashlib.sha256(message).digest(), 'big') % n
        t = (r + s) % n
        if t == 0:
            return False
        P1 = s * G + t * pubkey
        R = (e + P1.x()) % n
        return R == r
    
    @staticmethod
    def recover_private_key_from_k(r: int, s: int, k: int) -> int:
        """
        利用泄露的k和签名(r,s)恢复私钥
        """
        t = (s + r) % n
        if t == 0:
            raise ValueError("(s + r) must not be 0")
        t_inv = pow(t, -1, n)  # 模逆元
        return (k - s) * t_inv % n
    
if __name__ == "__main__":
    sm2 = SM2()
    pubkey = sm2.get_public_key()
    
    message = b"project5"

    print("原文:", message)

    # 加密
    ciphertext = sm2.encrypt(message, pubkey)
    print("密文(hex):", ciphertext.hex())

    # 解密
    plaintext = sm2.decrypt(ciphertext)
    print("解密结果:", plaintext.decode())

    # 签名
    signature = sm2.sign(message)
    print("签名: (r =", hex(signature[0]), ", s =", hex(signature[1]), ")")

    # 验签
    result = sm2.verify(message, signature, pubkey)
    print("验签结果:", result)

    
