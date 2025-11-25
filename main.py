#!/usr/bin/env python3
"""
自动化处理单个CVE的威胁情报生成工作流
整合所有脚本功能：
1. 使用 run_cve_ocr.py 搜索并使用OCR识别相关网页内容
2. 使用 web_txt_to_intel.py 从OCR结果中提取专业威胁情报
3. 使用 cve_intel_extractor.py 从NVD API获取详细技术数据
4. 使用 generate_threat_intel.py 生成MD格式的威胁情报
"""

import subprocess
import sys
import os
import argparse

def run_subprocess(cmd):
    """运行外部命令并返回结果"""
    print(f"正在执行: {' '.join(cmd)}")

    # 确保所有路径都已正确处理空格问题
    # 当使用 shell=False 时，参数列表会被直接传递给 exec，不需要额外引号

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        shell=False,
        # 将 cwd 设置为项目根目录，确保路径正确性
        cwd="/home/arldev/Threat Intelligence"
    )

    print(f"退出码: {result.returncode}")
    if result.stdout:
        print(f"标准输出:\n{result.stdout}")
    if result.stderr:
        print(f"标准错误:\n{result.stderr}")
    return result

def process_single_cve(cve_id):
    """处理单个CVE的完整流程"""
    print(f"\n{'='*70}")
    print(f"开始处理 CVE: {cve_id}")
    print(f"{'='*70}")

    # 确保目录存在
    for dir_name in ["scraped_data", "screenshots"]:
        os.makedirs(dir_name, exist_ok=True)

    # 定义处理步骤
    steps = [
        # 步骤1: 使用 run_cve_ocr.py 获取网页内容并OCR识别
        {
            "name": "OCR网页识别",
            "cmd": [sys.executable, "fast_playwright_scraper/run_cve_ocr.py", cve_id]
        },

        # 步骤2: 使用 web_txt_to_intel.py 提取威胁情报
        {
            "name": "提取威胁情报",
            "cmd": [sys.executable, "web_txt_to_intel.py", cve_id]
        },

        # 步骤3: 使用 cve_intel_extractor.py 获取NVD数据
        {
            "name": "获取NVD官方数据",
            "cmd": [sys.executable, "cve_intel_extractor.py", cve_id]
        },

        # 步骤4: 使用 generate_threat_intel.py 生成MD报告
        {
            "name": "生成MD格式报告",
            "cmd": [sys.executable, "generate_threat_intel.py", cve_id]
        }
    ]

    # 执行所有步骤
    all_success = True
    for step in steps:
        print(f"\n{'='*60}")
        print(f"步骤: {step['name']}")
        print(f"{'='*60}")

        result = run_subprocess(step['cmd'])

        if result.returncode != 0:
            print(f"\n[!] 警告: 步骤 '{step['name']}' 执行失败")
            all_success = False
        else:
            print(f"\n✓ 步骤 '{step['name']}' 执行成功")

    # 总结
    print(f"\n{'='*70}")
    if all_success:
        print(f"🎉 所有步骤执行成功！")
    else:
        print(f"⚠️  部分步骤执行失败！")

    print(f"处理结果已保存在 scraped_data/ 目录下")
    print(f"最终MD报告已生成：{cve_id}_intel_summary.md")
    print(f"{'='*70}")

    return all_success

def main():
    parser = argparse.ArgumentParser(
        description="自动化CVE威胁情报生成系统 - 单个CVE处理版本",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("cve_id", help="单个CVE编号（如CVE-2025-41115）")

    args = parser.parse_args()

    # 验证CVE格式
    if not args.cve_id.upper().startswith("CVE-"):
        print(f"[!] 错误：CVE格式不正确，请提供类似 CVE-2025-41115 的编号")
        return

    # 处理CVE
    process_single_cve(args.cve_id.upper())

if __name__ == "__main__":
    main()