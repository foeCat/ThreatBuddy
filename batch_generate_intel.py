#!/usr/bin/env python3
import subprocess
import sys

# 📌 指向你已有的生成脚本（请确保路径正确）
INTEL_SCRIPT = "/home/arldev/Threat Intelligence/generate_threat_intel.py"

CVE_LIST = [
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
if not os.path.isfile(INTEL_SCRIPT):
    print(f"❌ 错误: 找不到脚本 {INTEL_SCRIPT}")
    sys.exit(1)

print(f"✅ 使用情报生成器: {INTEL_SCRIPT}")
print(f"🚀 共 {len(CVE_LIST)} 个 CVE")

for i, cve in enumerate(CVE_LIST, 1):
    print(f"\n[{i}/{len(CVE_LIST)}] 生成报告: {cve}")
    try:
        subprocess.run([sys.executable, INTEL_SCRIPT, cve], check=True)
    except subprocess.CalledProcessError:
        print(f"❌ {cve} 生成失败")
    except KeyboardInterrupt:
        print("\n🛑 用户中断，退出。")
        break

print("\n🎉 Markdown 报告批量生成完成！")