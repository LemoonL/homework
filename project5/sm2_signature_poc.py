import hashlib
import secrets
from sm2 import SM2, G, n
from sm2_new import SM2_new

def test_leak_private_key():
    print("\n---------[1] 使用泄露的 k 恢复私钥--------")
    victim = SM2()
    print("真实私钥 d_A =", hex(victim.d))

    # 生成消息并签名（模拟签名过程）
    message = b"project5"
    e = int.from_bytes(hashlib.sha256(message).digest(), 'big') % n
    
    # 模拟签名过程并记录k（假设k已泄露）
    while True:
        k_leaked = secrets.randbelow(n - 1) + 1
        P1 = k_leaked * G
        r = (e + P1.x()) % n
        if r == 0 or r + k_leaked == n:
            continue
        s = ((k_leaked - r * victim.d) * pow(1 + victim.d, -1, n)) % n
        if s != 0:
            break
    
    print(f"签名 (r, s) = ({hex(r)}, {hex(s)})")
    print(f"泄露的 k = {hex(k_leaked)}")

    # 攻击：使用泄露的k恢复私钥
    try:
        recovered_d = SM2.recover_private_key_from_k(r, s, k_leaked)
        print("恢复的私钥 d_A' =", hex(recovered_d))
        print("攻击成功:", recovered_d == victim.d)
    except ValueError as e:
        print("攻击失败:", e)



def attack_reused_k(signature1: tuple, signature2: tuple, msg1: bytes, msg2: bytes, Z_A: bytes) -> int:
    """
    利用重用k的签名恢复私钥(同一用户)
    :param signature1: (r1, s1) 第一个消息的签名
    :param signature2: (r2, s2) 第二个消息的签名
    :param msg1: 第一个消息
    :param msg2: 第二个消息
    :param Z_A: 用户标识哈希值
    :return: 恢复的私钥d_A
    """
    r1, s1 = signature1
    r2, s2 = signature2
    
    # 计算两个消息的哈希值
    M1 = Z_A + msg1
    e1 = int.from_bytes(hashlib.sha256(M1).digest(), 'big') % n
    
    M2 = Z_A + msg2
    e2 = int.from_bytes(hashlib.sha256(M2).digest(), 'big') % n
    
    # 根据公式计算私钥
    numerator = (s2 - s1) % n
    denominator = (s1 - s2 + r1 - r2) % n
    
    # 如果分母为0，无法恢复私钥
    if denominator == 0:
        raise ValueError("无法恢复私钥：分母为0（可能是相同消息或无效签名）")
    
    # 计算分母的模逆元
    denom_inv = pow(denominator, -1, n)
    
    # 计算私钥
    d_A = numerator * denom_inv % n
    return d_A


def test_attack_reused_k():
    print("\n---------[2] 使用重复的 k 恢复私钥--------")
        # 创建受害者实例
    victim = SM2_new()
    print("真实私钥 d_A =", hex(victim.d))
    
    # 两条不同的消息
    msg1 = b"Transfer $100 to Alice"
    msg2 = b"Transfer $100 to Bob"
    
    # 使用相同的k为两条消息签名（模拟错误情况）
    k_reused = secrets.randbelow(n - 1) + 1
    sig1 = victim.sign(msg1, k=k_reused)
    sig2 = victim.sign(msg2, k=k_reused)
    
    print(f"消息1: {msg1}")
    print(f"签名1: (r1 = {hex(sig1[0])}, s1 = {hex(sig1[1])})")
    print(f"消息2: {msg2}")
    print(f"签名2: (r2 = {hex(sig2[0])}, s2 = {hex(sig2[1])})")
    print(f"重用的 k = {hex(k_reused)}")
    
    # 执行攻击
    try:
        recovered_d = attack_reused_k(sig1, sig2, msg1, msg2, victim.Z_A)
        print("\n恢复的私钥 d_A' =", hex(recovered_d))
        print("攻击成功:", recovered_d == victim.d)
    except ValueError as e:
        print("\n攻击失败:", e)
    
    # 验证恢复的私钥是否有效
    if recovered_d == victim.d:
        # 使用恢复的私钥创建新实例
        attacker = SM2_new(private_key=recovered_d)
        
        # 验证签名
        test_msg = b"Test message"
        test_sig = attacker.sign(test_msg)
        verification = attacker.verify(test_msg, test_sig, attacker.P)
        print("\n使用恢复私钥验证签名:", verification)


def attack_cross_user_reused_k(
    alice_sig: tuple, 
    bob_sig: tuple, 
    k: int
) -> tuple:
    """
    不同用户重用k时的交叉私钥恢复攻击
    :param alice_sig: Alice的签名(r1, s1)
    :param bob_sig: Bob的签名(r2, s2)
    :param k: 被重用的随机数
    :return: (Alice的私钥, Bob的私钥)
    """
    # Alice恢复Bob的私钥
    r2, s2 = bob_sig
    denominator_b = (s2 + r2) % n
    if denominator_b == 0:
        raise ValueError("Bob签名的(s2 + r2)不能为零")
    d_bob = (k - s2) * pow(denominator_b, -1, n) % n
    
    # Bob恢复Alice的私钥
    r1, s1 = alice_sig
    denominator_a = (s1 + r1) % n
    if denominator_a == 0:
        raise ValueError("Alice签名的(s1 + r1)不能为零")
    d_alice = (k - s1) * pow(denominator_a, -1, n) % n
    
    return d_alice, d_bob

def test_cross_user_reused_k():
    print("\n---------[3] 不同用户重用k的交叉攻击--------")
    
    alice = SM2_new(user_id=b"alice@example.com")
    bob = SM2_new(user_id=b"bob@example.org")
    
    print("Alice的真实私钥:", hex(alice.d))
    print("Bob的真实私钥:  ", hex(bob.d))
    
    # 两条不同的消息
    msg1 = b"Alice's confidential message"
    msg2 = b"Bob's secret document"
    
    # 使用相同的k为两个用户签名（模拟漏洞）
    k_shared = secrets.randbelow(n - 1) + 1
    print("\n共享的随机数k:", hex(k_shared))
    
    # 生成签名
    alice_sig = alice.sign(msg1, k_shared)
    bob_sig = bob.sign(msg2, k_shared)
    
    print("\nAlice的签名:")
    print(f"  r1 = {hex(alice_sig[0])}")
    print(f"  s1 = {hex(alice_sig[1])}")
    
    print("\nBob的签名:")
    print(f"  r2 = {hex(bob_sig[0])}")
    print(f"  s2 = {hex(bob_sig[1])}")
    
    # 交叉恢复私钥
    try:
        dA_recovered, dB_recovered = attack_cross_user_reused_k(alice_sig, bob_sig, k_shared)
        
        print("\n攻击结果:")
        print(f"恢复的Alice私钥: {hex(dA_recovered)}")
        print(f"是否正确: {dA_recovered == alice.d}")
        print(f"恢复的Bob私钥:   {hex(dB_recovered)}")
        print(f"是否正确: {dB_recovered == bob.d}")
        
        # 验证恢复的私钥
        test_msg = b"Test message for verification"
        
        # 使用恢复的Alice私钥验证
        alice_recovered = SM2_new(private_key=dA_recovered, user_id=b"alice@example.com")
        alice_sig_test = alice_recovered.sign(test_msg)
        valid = alice_recovered.verify(test_msg, alice_sig_test, alice_recovered.P)
        print("\n恢复的Alice私钥签名验证:", valid)
        
        # 使用恢复的Bob私钥验证
        bob_recovered = SM2_new(private_key=dB_recovered, user_id=b"bob@example.org")
        bob_sig_test = bob_recovered.sign(test_msg)
        valid = bob_recovered.verify(test_msg, bob_sig_test, bob_recovered.P)
        print("恢复的Bob私钥签名验证:  ", valid)
        
    except ValueError as e:
        print("\n交叉攻击失败:", e)

def test_same_d_k_with_ECDSA():
    print("\n---------[4] ECDSA中相同d,k --------")
    user = SM2_new(user_id=b"user@example.com")
    print(f"真实私钥 d = {hex(user.d)}")
    
    # 选择相同的随机数k
    k_shared = secrets.randbelow(n - 1) + 1
    print(f"共享的随机数 k = {hex(k_shared)}")
    
    # 两条不同的消息
    ecdsa_message = b"ECDSA signed message"
    sm2_message = b"SM2 signed message"
    
    # 使用相同的d和k生成签名
    try:
        ecdsa_sig = user.ecdsa_sign(ecdsa_message, k_shared)
        sm2_sig = user.sign(sm2_message, k_shared)
        
        print("\nECDSA签名:")
        print(f"  r1 = {hex(ecdsa_sig[0])}")
        print(f"  s1 = {hex(ecdsa_sig[1])}")
        
        print("\nSM2签名:")
        print(f"  r2 = {hex(sm2_sig[0])}")
        print(f"  s2 = {hex(sm2_sig[1])}")
        
        # 验证ECDSA签名
        ecdsa_valid = user.ecdsa_verify(ecdsa_message, ecdsa_sig, user.P)
        print("\nECDSA签名验证:", ecdsa_valid)
        
        # 验证SM2签名
        sm2_valid = user.verify(sm2_message, sm2_sig, user.P)
        print("SM2签名验证:  ", sm2_valid)
        
        # 从签名中恢复私钥d
        d_recovered = SM2_new.recover_private_key_from_shared_k(
            ecdsa_sig, sm2_sig, ecdsa_message
        )
        
        print("\n恢复的私钥 d' =", hex(d_recovered))
        print("恢复成功:", d_recovered == user.d)
        
        # 使用恢复的私钥创建新用户
        recovered_user = SM2_new(private_key=d_recovered, user_id=b"recovered_user")
        
        # 测试恢复的私钥能否用于签名
        test_msg = b"Test message for recovered key"
        
        # ECDSA签名验证
        test_ecdsa_sig = recovered_user.ecdsa_sign(test_msg)
        ecdsa_valid = recovered_user.ecdsa_verify(test_msg, test_ecdsa_sig, recovered_user.P)
        
        # SM2签名验证
        test_sm2_sig = recovered_user.sign(test_msg)
        sm2_valid = recovered_user.verify(test_msg, test_sm2_sig, recovered_user.P)
        
        print("\n恢复私钥的ECDSA签名验证:", ecdsa_valid)
        print("恢复私钥的SM2签名验证:  ", sm2_valid)
        
    except ValueError as e:
        print(f"\n签名失败: {e}")


if __name__ == "__main__":
    test_leak_private_key()
    test_attack_reused_k()
    test_cross_user_reused_k()
    test_same_d_k_with_ECDSA()