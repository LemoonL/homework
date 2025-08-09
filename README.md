# 山东大学 网络空间安全创新创业实践作业
## 202200460029 何翔
本仓库包含六个独立的密码学与安全相关项目，涵盖国密算法实现、优化、应用与零知识证明等内容。均由本人独立完成。各项目具体说明如下：

---

## Project 1: SM4 软件实现与优化
- 从SM4的基本实现出发，逐步优化SM4的软件执行效率。
- 优化内容包括：T-table、AES-NI、GFNI、VPROLD等指令集加速。
- 基于SM4实现，完成SM4-GCM工作模式的软件优化实现。

---

## Project 2: 基于数字水印的图片泄露检测
- 编程实现图片水印的嵌入与提取（可基于开源项目二次开发）。
- 对水印鲁棒性进行测试，包括但不限于：翻转、平移、截取、调对比度等操作。

---

## Project 3: circom实现poseidon2哈希算法电路
- 参考论文 Table1，参数选用(n,t,d)=(256,3,5)或(256,2,5)。
- 电路公开输入为poseidon2哈希值，隐私输入为哈希原像，仅考虑单block输入。
- 用Groth16算法生成零知识证明。
- 参考资料：
  1. [poseidon2哈希算法论文](https://eprint.iacr.org/2023/323.pdf)
  2. [circom官方文档](https://docs.circom.io/)
  3. [circom电路样例](https://github.com/iden3/circomlib)

---

## Project 4: SM3 软件实现与优化
- 参考SM4优化思路，对SM3基本实现进行多轮优化。
- 基于SM3实现，验证length-extension attack。
- 基于SM3实现，按RFC6962构建Merkle树（10万叶子节点），并实现叶子的存在性/不存在性证明。

---

## Project 5: SM2 软件实现与优化
- 用Python实现SM2基础算法及多种优化尝试。
- 参考20250713-wen-sm2-public.pdf，针对签名算法误用做PoC验证，给出推导文档与验证代码。
- 实现伪造中本聪数字签名的相关实验。

---

## Project 6: Google Password Checkup 协议验证
- 参考报告与论文 [Google Password Checkup](https://eprint.iacr.org/2019/723.pdf) section 3.1（Figure 2），实现该协议。

---

各项目详细流程、实验方法、结果分析等请参见对应子目录下的README文件。
