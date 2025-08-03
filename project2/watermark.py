import cv2
import numpy as np

def embed_watermark_dct(img_path, wm_bits, out_path, alpha=10):
    """
    使用DCT频域嵌入水印
    - img_path: 输入彩色图片路径
    - wm_bits: 水印比特列表（0/1）
    - out_path: 输出带水印图片路径
    - alpha: 嵌入强度参数，越大水印越明显但可能影响图像质量
    """
    img = cv2.imread(img_path, cv2.IMREAD_COLOR)
    if img is None:
        raise FileNotFoundError(f"Image not found: {img_path}")

    # 如果是4通道（带透明通道），去除透明通道
    if img.shape[2] == 4:
        img = img[:, :, :3]

    # 转换到YCrCb颜色空间，主要对亮度通道Y进行水印嵌入
    ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
    y_channel = ycrcb[:, :, 0].astype(np.float32)  # 亮度通道

    h, w = y_channel.shape
    block_size = 8  # DCT分块大小
    # 只处理能被8整除的尺寸部分，避免边界问题
    h_cropped = h - (h % block_size)
    w_cropped = w - (w % block_size)
    y_channel = y_channel[:h_cropped, :w_cropped]

    blocks_v = h_cropped // block_size  # 垂直块数
    blocks_h = w_cropped // block_size  # 水平块数

    pos = (4, 3)  # 选取中频DCT系数位置嵌入水印

    max_bits = blocks_v * blocks_h  # 最大可嵌入水印位数
    if len(wm_bits) > max_bits:
        raise ValueError(f"Watermark too long, max supported bits: {max_bits}")

    bit_idx = 0  # 当前嵌入水印bit索引
    y_dct_idct = np.zeros_like(y_channel)  # 保存处理后的Y通道数据

    # 遍历每个8x8块
    for i in range(blocks_v):
        for j in range(blocks_h):
            block = y_channel[i*block_size:(i+1)*block_size, j*block_size:(j+1)*block_size]
            dct_block = cv2.dct(block)  # DCT变换

            if bit_idx < len(wm_bits):
                # 根据水印比特调整DCT中频系数
                if wm_bits[bit_idx] == 1:
                    dct_block[pos] += alpha
                else:
                    dct_block[pos] -= alpha
                bit_idx += 1

            idct_block = cv2.idct(dct_block)  # 逆DCT恢复块
            y_dct_idct[i*block_size:(i+1)*block_size, j*block_size:(j+1)*block_size] = idct_block

    # 将修改后的Y通道限制到[0,255]，合成新图像
    ycrcb[:h_cropped, :w_cropped, 0] = np.clip(y_dct_idct, 0, 255).astype(np.uint8)
    watermarked = cv2.cvtColor(ycrcb, cv2.COLOR_YCrCb2BGR)  # 转回BGR
    cv2.imwrite(out_path, watermarked)
    print(f"[*] Watermark embedded: {out_path}")

def orb_match_score(img1, img2):
    """
    计算两张图的ORB特征匹配平均距离（距离越小匹配越好）
    """
    orb = cv2.ORB_create(5000)
    kp1, des1 = orb.detectAndCompute(img1, None)
    kp2, des2 = orb.detectAndCompute(img2, None)
    if des1 is None or des2 is None:
        return float('inf')
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matches = bf.match(des1, des2)
    if len(matches) == 0:
        return float('inf')
    avg_dist = sum(m.distance for m in matches) / len(matches)
    return avg_dist

def geometric_align_flip_correction(img_path, ref_path):
    """
    自动检测攻击图是否左右翻转，若翻转则先翻回
    然后用ORB匹配计算单应矩阵，做几何校正对齐
    返回对齐后的图像
    """
    img = cv2.imread(img_path, cv2.IMREAD_COLOR)
    ref = cv2.imread(ref_path, cv2.IMREAD_COLOR)
    if img is None or ref is None:
        raise FileNotFoundError("Image(s) not found")

    # 计算未翻转和翻转后的ORB匹配距离
    score_normal = orb_match_score(img, ref)
    img_flip = cv2.flip(img, 1)  # 水平翻转
    score_flip = orb_match_score(img_flip, ref)

    # 判断哪种匹配距离更小，选择更相似的图像继续校正
    if score_flip < score_normal:
        print("[INFO] Detected flipped attack image, correcting flip")
        img_to_align = img_flip
    else:
        img_to_align = img

    # ORB特征检测与匹配
    orb = cv2.ORB_create(5000)
    kp1, des1 = orb.detectAndCompute(img_to_align, None)
    kp2, des2 = orb.detectAndCompute(ref, None)
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matches = bf.match(des1, des2)
    matches = sorted(matches, key=lambda x: x.distance)[:100]

    if len(matches) < 10:
        print("[WARN] Not enough matches for geometric alignment")
        return img_to_align

    pts_img = np.float32([kp1[m.queryIdx].pt for m in matches])
    pts_ref = np.float32([kp2[m.trainIdx].pt for m in matches])

    # 利用RANSAC估计单应矩阵
    H, mask = cv2.findHomography(pts_img, pts_ref, cv2.RANSAC, 5.0)
    if H is None:
        print("[WARN] Homography estimation failed")
        return img_to_align

    height, width = ref.shape[:2]
    aligned = cv2.warpPerspective(img_to_align, H, (width, height))  # 几何校正对齐
    return aligned

def extract_watermark_dct_geom_sync_flip_correct(wm_img_path, orig_img_path, wm_len, alpha=10):
    """
    提取水印：
    - 先自动检测并矫正翻转攻击
    - 利用ORB几何校正图像
    - 对齐后计算每块DCT系数差提取水印比特
    """
    aligned_img = geometric_align_flip_correction(wm_img_path, orig_img_path)
    cv2.imwrite("aligned_flip_corrected.png", aligned_img)  # 保存校正图便于调试

    orig_img = cv2.imread(orig_img_path, cv2.IMREAD_COLOR)
    if orig_img is None:
        raise FileNotFoundError("Original image not found")

    # 去除透明通道（如果存在）
    if aligned_img.shape[2] == 4:
        aligned_img = aligned_img[:, :, :3]
    if orig_img.shape[2] == 4:
        orig_img = orig_img[:, :, :3]

    # 转YCrCb
    wm_ycrcb = cv2.cvtColor(aligned_img, cv2.COLOR_BGR2YCrCb)
    orig_ycrcb = cv2.cvtColor(orig_img, cv2.COLOR_BGR2YCrCb)

    h, w = wm_ycrcb.shape[:2]
    block_size = 8
    h_cropped = h - (h % block_size)
    w_cropped = w - (w % block_size)

    wm_y = wm_ycrcb[:h_cropped, :w_cropped, 0].astype(np.float32)
    orig_y = orig_ycrcb[:h_cropped, :w_cropped, 0].astype(np.float32)

    blocks_v = h_cropped // block_size
    blocks_h = w_cropped // block_size

    pos = (4, 3)  # 中频DCT系数位置
    bits = []
    bit_idx = 0

    for i in range(blocks_v):
        for j in range(blocks_h):
            if bit_idx >= wm_len:
                break
            wm_block = wm_y[i*block_size:(i+1)*block_size, j*block_size:(j+1)*block_size]
            orig_block = orig_y[i*block_size:(i+1)*block_size, j*block_size:(j+1)*block_size]

            wm_dct = cv2.dct(wm_block)
            orig_dct = cv2.dct(orig_block)

            # 差值正负判断水印bit
            diff = wm_dct[pos] - orig_dct[pos]
            bits.append(1 if diff > 0 else 0)

            bit_idx += 1
        if bit_idx >= wm_len:
            break
    return bits

def attack_image_color(img_path, attack_type, out_path):
    """
    简单攻击模拟：
    - flip：水平翻转
    - translate：平移5像素
    - crop：裁剪中间一部分再缩放回原大小
    - contrast：调高对比度
    """
    img = cv2.imread(img_path, cv2.IMREAD_COLOR)
    if img is None:
        raise FileNotFoundError(f"Image not found: {img_path}")

    if attack_type == 'flip':
        img = cv2.flip(img, 1)
    elif attack_type == 'translate':
        rows, cols = img.shape[:2]
        M = np.float32([[1, 0, 5], [0, 1, 5]])
        img = cv2.warpAffine(img, M, (cols, rows))
    elif attack_type == 'crop':
        h, w = img.shape[:2]
        img = img[h//4:h*3//4, w//4:w*3//4]
        img = cv2.resize(img, (w, h))
    elif attack_type == 'contrast':
        hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
        hsv[:, :, 2] = cv2.convertScaleAbs(hsv[:, :, 2], alpha=1.5, beta=0)
        img = cv2.cvtColor(hsv, cv2.COLOR_HSV2BGR)
    else:
        raise ValueError(f"Unknown attack: {attack_type}")

    cv2.imwrite(out_path, img)
    print(f"[*] Attack done: {out_path}")

def evaluate(original_bits, extracted_bits):
    """
    计算比特误码率（BER）
    """
    errors = sum(o != e for o, e in zip(original_bits, extracted_bits))
    return errors / len(original_bits)

def main():
    original_img = 'sample.png' 
    watermarked_img = 'watermarked_dct.png'
    watermark_bits = [1,0,1,1,0,0,1,0,1,1,0,1,1,0,0,1,0,1,0,1]  # 水印比特序列

    print("[*] Embedding watermark...")
    embed_watermark_dct(original_img, watermark_bits, watermarked_img, alpha=15)

    print("[*] Attacking and extracting watermark with geometric sync + flip correction:")
    for atk in ['flip', 'translate', 'crop', 'contrast']:
        attacked_path = f'attacked_{atk}.png'
        attack_image_color(watermarked_img, atk, attacked_path)
        extracted = extract_watermark_dct_geom_sync_flip_correct(attacked_path, original_img, len(watermark_bits), alpha=15)
        ber = evaluate(watermark_bits, extracted)
        print(f"[{atk.upper()}] Extracted watermark: {extracted}")
        print(f"[{atk.upper()}] BER: {ber:.2f}")

if __name__ == '__main__':
    main()
