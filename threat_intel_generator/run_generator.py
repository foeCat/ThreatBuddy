#!/usr/bin/env python3
"""
Threat Intel Generator CLI 入口
"""

import sys
sys.path.insert(0, '/home/arldev/ThreatBuddy')

from threat_intel_generator.main_generator import ThreatIntelGenerator

def main():
    if len(sys.argv) != 2:
        print("Usage: python run_generator.py CVE-XXXX-XXXXX", file=sys.stderr)
        sys.exit(1)

    cve_id = sys.argv[1].strip()

    try:
        generator = ThreatIntelGenerator()
        report = generator.generate_md_report(cve_id)

        # 输出到终端和文件
        output_file = f"results/{cve_id}_intel_summary.md"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[+] 已生成报告: {output_file}")
        print("\n" + "="*50)
        print(report)
    except ValueError as e:
        print(f"[!] 配置错误: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

