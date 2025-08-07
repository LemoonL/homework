import time
from sm2 import SM2
from sm2_window_opt import SM2_window_opt

def main():
    sm2 = SM2()
    pubkey = sm2.get_public_key()
    msg = b"project5"
    print("\n加密明文:", msg)

    # 普通SM2加解密计时
    start = time.time()
    ct = sm2.encrypt(msg, pubkey)
    pt = sm2.decrypt(ct)
    end = time.time()
    t = end - start
    print("\n[SM2]")
    print("密文(hex):", ct.hex())
    print("解密明文:", pt.decode())
    print(f"加解密用时: {t:.6f} 秒")

    sm2_w = SM2_window_opt()
    message = "project5"
    # 优化SM2加解密计时
    start_opt = time.time()

    ct_opt = sm2_w.encrypt(message, use_window=True)
    pt_opt = sm2_w.decrypt(ct_opt)

    end_opt = time.time()
    t_opt = end_opt - start_opt

    print("\n[优化SM2]")
    print("密文(hex):", ct_opt.hex())
    print("解密明文:", pt_opt)
    print(f"加解密用时: {t_opt:.6f} 秒")

if __name__ == "__main__":
    main()
