#!/usr/bin/env python3
"""
CVE Intel Extractor CLI 入口
"""

import sys
import json
import os
from main_extractor import CVEIntelExtractor

def main():
    if len(sys.argv) != 2:
        print("Usage: python run_extractor.py CVE-XXXX-XXXXX", file=sys.stderr)
        sys.exit(1)

    cve_id = sys.argv[1].strip()

    # 初始化提取器
    extractor = CVEIntelExtractor()

    # 提取情报
    intel = extractor.fetch_cve_intel(cve_id)

    if intel is None:
        print("null")
        sys.exit(1)

    # 输出到 stdout
    output_json = json.dumps(intel, ensure_ascii=False, separators=(',', ':'))
    print(output_json)

    # 保存到本地文件
    output_dir = "scraped_data"
    os.makedirs(output_dir, exist_ok=True)

    filename = os.path.join(output_dir, f"{cve_id.upper()}.json")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(json.dumps(intel, ensure_ascii=False, indent=2))

    print(f"[+] 已保存原始情报到: {filename}", file=sys.stderr)

if __name__ == "__main__":
    main()
