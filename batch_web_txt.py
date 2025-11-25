#!/usr/bin/env python3
import subprocess
import sys

# 📌 指向你实际的脚本：web_txt_to_intel.py
EXTRACTOR = "/home/arldev/Threat Intelligence/web_txt_to_intel.py"

CVEs = [
    "CVE-2025-41115",
    "CVE-2025-49752",
    "CVE-2025-63216",
    "CVE-2025-63224",
    "CVE-2025-65108",
    "CVE-2024-44659",
    "CVE-2025-10437",
    "CVE-2025-11127",
    "CVE-2025-11456",
    "CVE-2025-12057",
    "CVE-2025-13284",
    "CVE-2025-41346",
    "CVE-2025-41347",
    "CVE-2025-41348",
    "CVE-2025-41733"
]

# 检查脚本是否存在
import os
if not os.path.isfile(EXTRACTOR):
    print(f"❌ 错误: 找不到脚本 {EXTRACTOR}")
    sys.exit(1)

print(f"✅ 使用提取器: {EXTRACTOR}")
print(f"🚀 共 {len(CVEs)} 个 CVE")

for i, cve in enumerate(CVEs, 1):
    print(f"\n[{i}/{len(CVEs)}] 正在处理: {cve}")
    try:
        subprocess.run([sys.executable, EXTRACTOR, cve], check=True)
    except subprocess.CalledProcessError:
        print(f"❌ {cve} 处理失败")
    except KeyboardInterrupt:
        print("\n🛑 用户中断，退出。")
        break

print("\n🎉 批量任务完成！")