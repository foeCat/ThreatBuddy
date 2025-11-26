#!/usr/bin/env python3
"""
批量生成威胁情报报告脚本
根据 scraped_data 目录中的 JSON 文件批量生成报告
"""
import sys
from pathlib import Path
import os
sys.path.append(str(Path(__file__).parent))

from threat_intel_generator.main_generator import ThreatIntelGenerator

DATA_DIR = "./scraped_data"

def main():
    if not os.path.exists(DATA_DIR):
        print(f"missing: {DATA_DIR}", file=sys.stderr)
        sys.exit(1)

    # 从scraped_data目录获取所有JSON文件
    json_files = [f for f in os.listdir(DATA_DIR) if f.endswith('.json')]
    if not json_files:
        print(f"no JSON files found in {DATA_DIR}", file=sys.stderr)
        sys.exit(1)

    # 提取CVE ID（去掉.json扩展名）
    cves = [f[:-5] for f in json_files]
    print(f"start: {len(cves)} CVEs", file=sys.stderr)

    # 初始化威胁情报生成器
    try:
        generator = ThreatIntelGenerator()
    except ValueError as e:
        print(f"初始化生成器失败: {e}", file=sys.stderr)
        sys.exit(1)

    # 批量生成报告
    for cve in cves:
        try:
            print(f"processing: {cve}", file=sys.stderr)
            report = generator.generate_md_report(cve)
            if report.startswith("# 错误"):
                print(f"{cve} failed", file=sys.stderr)
            else:
                # 保存报告到 results 目录
                report_path = os.path.join("./results", f"{cve}_report.md")
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write(report)
                print(f"{cve} success (saved to results)", file=sys.stderr)
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception as e:
            print(f"{cve} failed: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()