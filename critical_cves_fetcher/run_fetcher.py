#!/usr/bin/env python3
"""
Critical CVE Fetcher CLI 入口
"""

import sys
from main_fetcher import CriticalCVEsFetcher

DAYS_AGO = 7
MIN_CVSS = 9.0

def main():
    # 初始化提取器
    fetcher = CriticalCVEsFetcher()

    # 获取关键 CVE
    cves = fetcher.fetch_critical_cves(days_ago=DAYS_AGO, min_cvss=MIN_CVSS)

    # 输出结果
    for score, cve_id in cves:
        print(f"{cve_id} (CVSS: {score})")

if __name__ == "__main__":
    main()
