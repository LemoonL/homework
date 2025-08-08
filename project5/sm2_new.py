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

class SM2_new:
    def __init__(self, private_key: int = None,user_id: bytes = None):
        if private_key:
            self.d = private_key
        else:
            self.d = secrets.randbelow(n - 1) + 1
        self.P = self.d * G
        # 假设的固定用户标识参数
        # self.ID_A = b"ALICE@EMAIL.COM"
        self.ID_A = user_id if user_id else b"ALICE@EMAIL.COM"
        self.ENTL_A = int_to_bytes(len(self.ID_A) * 8, 2)
        self.Z_A = self.compute_ZA()

    def compute_ZA(self) -> bytes:
        """计算ZA值（用户标识哈希）"""
        data = self.ENTL_A + self.ID_A + int_to_bytes(a, 32) + int_to_bytes(b, 32) + \
               int_to_bytes(Gx, 32) + int_to_bytes(Gy, 32) + \
               int_to_bytes(self.P.x(), 32) + int_to_bytes(self.P.y(), 32)
        return hashlib.sha256(data).digest()

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

    def sign(self, message: bytes, k: int = None) -> tuple:
        """签名函数，允许传入特定的k值（用于演示重用k攻击）"""
        M = self.Z_A + message
        e = int.from_bytes(hashlib.sha256(M).digest(), 'big') % n
        
        if k is None:
            # 正常情况：随机生成k
            k = secrets.randbelow(n - 1) + 1
        
        P1 = k * G
        r = (e + P1.x()) % n
        
        # 检查r是否有效
        if r == 0 or r + k == n:
            # 如果无效，递归调用（正常使用时应该重试）
            return self.sign(message, k=None)
        
        # 计算s
        s = ((k - r * self.d) * pow(1 + self.d, -1, n)) % n
        
        # 检查s是否有效
        if s == 0:
            return self.sign(message, k=None)
        
        return r, s

    def verify(self, message: bytes, signature: tuple, pubkey: ellipticcurve.Point) -> bool:
        r, s = signature
        if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
            return False
        
        # 计算ZA（需要根据公钥重新计算）
        entl_a = int_to_bytes(len(self.ID_A) * 8, 2)
        data = entl_a + self.ID_A + int_to_bytes(a, 32) + int_to_bytes(b, 32) + \
               int_to_bytes(Gx, 32) + int_to_bytes(Gy, 32) + \
               int_to_bytes(pubkey.x(), 32) + int_to_bytes(pubkey.y(), 32)
        Z_A = hashlib.sha256(data).digest()
        
        M = Z_A + message
        e = int.from_bytes(hashlib.sha256(M).digest(), 'big') % n
        t = (r + s) % n
        
        if t == 0:
            return False
        
        P1 = s * G + t * pubkey
        R = (e + P1.x()) % n
        return R == r
    
    def recover_private_key_from_k(self, signature: tuple, k: int) -> int:
        """
        从已知的k和签名恢复私钥
        :param signature: (r, s) 签名
        :param k: 签名使用的随机数
        :return: 恢复的私钥
        """
        r, s = signature
        denominator = (s + r) % n
        if denominator == 0:
            raise ValueError("分母(s + r)不能为零")
        denom_inv = pow(denominator, -1, n)
        return (k - s) * denom_inv % n
    
    # ============== ECDSA签名和共用k攻击 ==============
    
    def ecdsa_sign(self, message: bytes, k: int = None) -> tuple:
        """
        ECDSA签名
        :param message: 待签名消息
        :param k: 随机数（可选）
        :return: 签名(r, s)
        """
        if k is None:
            k = secrets.randbelow(n - 1) + 1
            
        # 计算R = kG
        R = k * G
        r = R.x() % n
        if r == 0:
            raise ValueError("r不能为0，请重选k")
        
        # 计算消息哈希
        e = int.from_bytes(hashlib.sha256(message).digest(), 'big') % n
        
        # 计算s = k^{-1}(e + r*d) mod n
        k_inv = pow(k, -1, n)
        s = k_inv * (e + r * self.d) % n
        if s == 0:
            raise ValueError("s不能为0，请重选k")
        
        return r, s
    
    def ecdsa_verify(self, message: bytes, signature: tuple, pubkey: ellipticcurve.Point) -> bool:
        """
        ECDSA签名验证
        :param message: 原始消息
        :param signature: 签名(r, s)
        :param pubkey: 公钥
        :return: 验证结果
        """
        r, s = signature
        if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
            return False
        
        # 计算消息哈希
        e = int.from_bytes(hashlib.sha256(message).digest(), 'big') % n
        
        # 计算w = s^{-1} mod n
        w = pow(s, -1, n)
        
        # 计算u1 = e*w mod n, u2 = r*w mod n
        u1 = e * w % n
        u2 = r * w % n
        
        # 计算点P = u1*G + u2*pubkey
        P = u1 * G + u2 * pubkey
        
        # 验证r是否等于P.x mod n
        return r == P.x() % n
    
    @staticmethod
    def recover_private_key_from_shared_k(
        ecdsa_sig: tuple, 
        sm2_sig: tuple, 
        ecdsa_message: bytes
    ) -> int:
        """
        从ECDSA和SM2共用k的签名中恢复私钥d
        :param ecdsa_sig: ECDSA签名(r1, s1)
        :param sm2_sig: SM2签名(r2, s2)
        :param ecdsa_message: ECDSA签名的原始消息
        :return: 恢复的私钥d
        """
        r1, s1 = ecdsa_sig
        r2, s2 = sm2_sig
        
        # 计算ECDSA的消息哈希
        e1 = int.from_bytes(hashlib.sha256(ecdsa_message).digest(), 'big') % n
        
        # 根据公式推导私钥d
        numerator = (s1 * s2 - e1) % n
        denominator = (r1- s1 * (s2 + r2 ))% n
        
        if denominator == 0:
            raise ValueError("分母为0，无法恢复私钥")
        
        denom_inv = pow(denominator, -1, n)
        d_recovered = numerator * denom_inv % n
        return d_recovered
        
    def forge_ecdsa_signature_without_message_check(self, pubkey: ellipticcurve.Point):
        """
        构造伪造ECDSA签名（只验证e而不验证原始消息m时）
        :param pubkey: 被伪造者的公钥（如“中本聪”的）
        :return: (r', s', e') 构造的伪造签名和消息哈希
        """
        # Step 1: 随机选取 u, v
        u = secrets.randbelow(n - 1) + 1
        v = secrets.randbelow(n - 1) + 1

        # Step 2: 构造 R' = uG + vP
        R = u * G + v * pubkey
        r_prime = R.x() % n

        # Step 3: 计算 s' = r' * v^{-1} mod n
        v_inv = pow(v, -1, n)
        s_prime = r_prime * v_inv % n

        # Step 4: 计算 e' = r' * u * v^{-1} mod n
        e_prime = r_prime * u * v_inv % n

        return (r_prime, s_prime, e_prime)

if __name__ == "__main__":
    sm2 = SM2_new()
    pubkey = sm2.get_public_key()

    # 构造伪造签名
    r_forged, s_forged, e_forged = sm2.forge_ecdsa_signature_without_message_check(pubkey)

    print("[*] Forged Signature:")
    print(f"r = {hex(r_forged)}")
    print(f"s = {hex(s_forged)}")
    print(f"e (fake hash) = {hex(e_forged)}")

    # 构造一个假的“hash(m)”直接提供给验证器
    def verify_only_e(r, s, e, pubkey):
        if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
            return False
        w = pow(s, -1, n)
        u1 = e * w % n
        u2 = r * w % n
        R = u1 * G + u2 * pubkey
        return R.x() % n == r

    print("[*] Verifying forged signature...")
    ok = verify_only_e(r_forged, s_forged, e_forged, pubkey)
    print("Verification passed!" if ok else "Verification failed!")
