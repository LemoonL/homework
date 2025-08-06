from ecdsa import NIST256p
from phe import paillier
import hashlib

# 初始化 ECC 群
curve = NIST256p
G = curve.generator
order = G.order()

def hash_to_point(data: str):
    digest = hashlib.sha256(data.encode()).digest()
    h = int.from_bytes(digest, 'big') % order
    return h * G

class AHE:
    def __init__(self):
        self.pubkey, self.privkey = paillier.generate_paillier_keypair()
    def encrypt(self, m: int):
        return self.pubkey.encrypt(m)
    def decrypt(self, c):
        return self.privkey.decrypt(c)
