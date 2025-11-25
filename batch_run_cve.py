#!/usr/bin/env python3
import subprocess
import sys
import os

# === 关键：明确指定 run_cve_ocr.py 的完整路径（带空格也没事）===
RUN_SCRIPT = "/home/arldev/Threat Intelligence/fast_playwright_scraper/run_cve_ocr.py"

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
    "CVE-2025-41733",
    "CVE-2025-41734",
    "CVE-2025-52410",
    "CVE-2025-54321",
    "CVE-2025-59245",
    "CVE-2025-60738",
    "CVE-2025-63206",
    "CVE-2025-63207",
    "CVE-2025-63210",
    "CVE-2025-63213",
    "CVE-2025-63217",
    "CVE-2025-63218",
    "CVE-2025-63223",
    "CVE-2025-63225",
    "CVE-2025-63228",
    "CVE-2025-63685",
    "CVE-2025-63694",
    "CVE-2025-63695",
    "CVE-2025-63747",
    "CVE-2025-63807",
    "CVE-2025-63888",
    "CVE-2025-64310",
    "CVE-2025-9312",
    "CVE-2025-10571",
    "CVE-2025-40547",
    "CVE-2025-40548",
    "CVE-2025-40549",
    "CVE-2025-56643",
    "CVE-2025-64767",
    "CVE-2025-65021",
    "CVE-2025-9501"
]

def main():
    # 检查脚本是否存在
    if not os.path.isfile(RUN_SCRIPT):
        print(f"❌ 致命错误: 找不到 run_cve_ocr.py")
        print(f"   路径: {RUN_SCRIPT}")
        print("   请确认文件名是否拼写正确（注意 scraper 后有没有 t？）")
        sys.exit(1)

    print(f"✅ 使用脚本: {RUN_SCRIPT}")
    print(f"🚀 共 {len(CVE_LIST)} 个 CVE 待处理\n")

    for i, cve in enumerate(CVE_LIST, 1):
        print(f"[{i}/{len(CVE_LIST)}] 处理中: {cve}")
        try:
            # 直接使用绝对路径调用，列表形式，不经过 shell → 空格安全！
            subprocess.run(
                [sys.executable, RUN_SCRIPT, cve],
                check=True,
                stdout=sys.stdout,
                stderr=sys.stderr,
                text=True
            )
        except subprocess.CalledProcessError as e:
            print(f"❌ {cve} 失败 (退出码: {e.returncode})")
        except KeyboardInterrupt:
            print("\n🛑 中断，退出。")
            break

    print("\n🎉 批量任务结束！")

if __name__ == "__main__":
    main()