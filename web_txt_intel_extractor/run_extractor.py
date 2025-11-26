#!/usr/bin/env python3
"""
Web TXT Intel Extractor CLI 入口
"""

import sys
import argparse
import asyncio
from main_extractor import WebTxtIntelExtractor


async def main():
    parser = argparse.ArgumentParser(description="从 .txt 提取专业威胁情报（单次 LLM 调用）")
    parser.add_argument("cve_id", help="CVE 编号，例如 CVE-2025-41115")
    parser.add_argument("--stdout", action="store_true", help="输出到 stdout")

    args = parser.parse_args()
    cve_id = args.cve_id.upper()

    try:
        extractor = WebTxtIntelExtractor()
    except ValueError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    text = extractor.read_txt_file(cve_id)
    if not text:
        summary = "错误：未能读取输入文件。"
    else:
        summary = await extractor.extract_summary(text, cve_id)

    if args.stdout:
        print(summary)
    else:
        extractor.save_summary(cve_id, summary)


if __name__ == "__main__":
    asyncio.run(main())
