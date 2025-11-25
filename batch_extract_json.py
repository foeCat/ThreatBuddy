#!/usr/bin/env python3
import subprocess
import sys
import os

# === 指定 cve_intel_extractor.py 的完整路径 ===
EXTRACT_SCRIPT = "/home/arldev/Threat Intelligence/cve_intel_extractor.py"

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

def main():
    # 检查提取脚本是否存在
    if not os.path.isfile(EXTRACT_SCRIPT):
        print(f"❌ 致命错误: 找不到 cve_intel_extractor.py")
        print(f"   路径: {EXTRACT_SCRIPT}")
        sys.exit(1)

    print(f"✅ 使用提取脚本: {EXTRACT_SCRIPT}")
    print(f"🚀 共 {len(CVE_LIST)} 个 CVE 待处理\n")

    for i, cve in enumerate(CVE_LIST, 1):
        print(f"[{i}/{len(CVE_LIST)}] 提取中: {cve}")
        try:
            # 调用 cve_intel_extractor.py
            result = subprocess.run(
                [sys.executable, EXTRACT_SCRIPT, cve],
                capture_output=True,
                text=True,
                check=True
            )
            # 可选：打印成功信息（或只依赖 extractor 自身输出）
            if "[+] 已保存原始情报到:" in result.stdout:
                print(f"✓ 成功保存 {cve}.json")
            else:
                print(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"❌ {cve} 失败 (退出码: {e.returncode})")
            print(e.stderr or e.output)
        except KeyboardInterrupt:
            print("\n🛑 用户中断，退出。")
            break

    print("\n🎉 JSON 批量提取任务结束！")
    print(f"📁 结果默认保存在: scraped_data/")

if __name__ == "__main__":
    main()