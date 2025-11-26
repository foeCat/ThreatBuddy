#!/usr/bin/env python3
import os
import sys
import json
import asyncio
import subprocess
from pathlib import Path

sys.path.insert(0, '.')

from cve_intel_extractor import CVEIntelExtractor
from web_txt_intel_extractor import WebTxtIntelExtractor
from critical_cves_fetcher import CriticalCVEsFetcher

try:
    from threat_intel_generator import ThreatIntelGenerator
except ImportError:
    ThreatIntelGenerator = None


async def fetch_cve_list():
    print("[1/6] 使用 critical_cves_fetcher 获取 CVE 列表...")
    cve_list_dir = Path("scraped_data/cve_lists")
    cve_list_dir.mkdir(parents=True, exist_ok=True)
    list_file = cve_list_dir / "latest_cves.txt"

    cve_list = []

    # 尝试从 fetcher 获取最新 CVE
    try:
        fetcher = CriticalCVEsFetcher()
        cve_tuples = fetcher.fetch_critical_cves()
        if cve_tuples:
            cve_list = [cve_id for (score, cve_id) in cve_tuples]
            # 成功则更新 latest_cves.txt
            with open(list_file, "w", encoding="utf-8") as f:
                for cve in cve_list:
                    f.write(cve + "\n")
            print(f"[+] 共获取到 {len(cve_list)} 个 CVE")
            print(f"[+] CVE 列表已保存到 {list_file}")
        else:
            print("[!] critical_cves_fetcher 返回空列表")
    except Exception as e:
        print(f"[!] critical_cves_fetcher 调用失败: {e}")

    # 如果没拿到新数据，尝试从本地文件 fallback
    if not cve_list:
        print("[~] 尝试从本地缓存加载 CVE 列表...")
        if list_file.exists():
            try:
                with open(list_file, "r", encoding="utf-8") as f:
                    cve_list = [line.strip() for line in f if line.strip()]
                print(f"[~] 从 {list_file} 加载了 {len(cve_list)} 个 CVE")
            except Exception as e:
                print(f"[!] 读取缓存文件失败: {e}")
        else:
            print("[!] 无缓存文件可用")

    return cve_list


async def run_playwright_scraper(cve_id):
    print(f"[2/6] 使用 playwright 抓取 {cve_id} 信息...")
    scraper_path = Path("fast_playwright_scraper/run_cve_ocr.py")

    if not scraper_path.exists():
        print(f"[!] 未找到 playwright scraper 脚本: {scraper_path}")
        return False

    try:
        result = subprocess.run(
            [sys.executable, str(scraper_path), cve_id],
            capture_output=True,
            text=True,
            check=True
        )

        if result.returncode == 0:
            print(f"[+] {cve_id} 抓取成功")
            return True
        else:
            print(f"[!] {cve_id} 抓取失败: {result.stderr}")
            return False

    except subprocess.CalledProcessError as e:
        print(f"[!] {cve_id} 抓取失败: {e.stderr}")
        return False
    except Exception as e:
        print(f"[!] {cve_id} 抓取失败: {e}")
        return False


async def fetch_cve_json(cve_id):
    json_path = Path(f"scraped_data/{cve_id}.json")
    
    # 👇 新增：如果本地已有 JSON，直接返回成功
    if json_path.exists():
        print(f"[~] {cve_id} JSON 已存在，跳过 NVD API 调用")
        return True

    print(f"[3/6] 获取 {cve_id} JSON 信息...")
    try:
        extractor = CVEIntelExtractor()
        cve_data = extractor.fetch_cve_intel(cve_id)

        if not cve_data:
            print(f"[!] {cve_id} NVD API 请求失败")
            return False

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(cve_data, f, ensure_ascii=False, indent=2)

        print(f"[+] {cve_id} JSON 信息已保存")
        return True

    except Exception as e:
        print(f"[!] {cve_id} JSON 信息获取失败: {e}")
        return False


async def extract_txt_intel(cve_id):
    print(f"[4/6] 提取 {cve_id} TXT 情报...")
    try:
        extractor = WebTxtIntelExtractor()
        text = extractor.read_txt_file(cve_id)

        if not text:
            print(f"[!] {cve_id} TXT 文件不存在或无法读取")
            return False

        summary = await extractor.extract_summary(text, cve_id)
        extractor.save_summary(cve_id, summary)

        print(f"[+] {cve_id} TXT 情报已提取")
        return True

    except Exception as e:
        print(f"[!] {cve_id} TXT 情报提取失败: {e}")
        return False


async def process_single_cve(cve_id):
    print(f"\n🔄 处理 CVE: {cve_id}")
    Path("scraped_data").mkdir(exist_ok=True)

    txt_path = Path(f"scraped_data/{cve_id}.txt")
    json_path = Path(f"scraped_data/{cve_id}.json")

    # 第2步：Playwright 抓取（仅当 .txt 不存在时才运行）
    scrape_success = False
    if not txt_path.exists():
        try:
            scrape_success = await run_playwright_scraper(cve_id)
        except Exception as e:
            print(f"[!] Playwright 抓取出错: {e}")
            scrape_success = False
    else:
        print(f"[~] {cve_id} TXT 已存在，跳过 Playwright 抓取")
        scrape_success = True  # 视为成功，因为已有数据

    # 如果抓取失败且没有 TXT 文件，跳过后续
    if not txt_path.exists():
        print(f"[!] {cve_id} TXT 文件不存在，跳过后续处理")
        return False

    # 第3步：获取 JSON（仅当 .json 不存在时才调用 NVD API）
    json_success = False
    if not json_path.exists():
        json_success = await fetch_cve_json(cve_id)
    else:
        print(f"[~] {cve_id} JSON 已存在，跳过 NVD API 调用")
        json_success = True

    # 第4步：提取 TXT 情报（只要有 TXT 就尝试提取）
    txt_success = await extract_txt_intel(cve_id)

    if json_success or txt_success or scrape_success:
        print(f"[+] {cve_id} 处理完成")
        return True
    else:
        print(f"❌ {cve_id} 处理失败")
        return False


async def main():
    print("🚀 启动自动威胁情报生成系统")
    print("=" * 50)

    try:
        cve_list = await fetch_cve_list()

        if not cve_list:
            print("[!] 未获取到任何可处理的 CVE")
            return

        print("=" * 50)

        success_count = 0
        for cve_id in cve_list:
            if await process_single_cve(cve_id):
                success_count += 1

        print("\n" + "=" * 50)
        print(f"🎉 处理完成！成功处理 {success_count}/{len(cve_list)} 个 CVE")

    except KeyboardInterrupt:
        print("\n🛑 用户中断操作")
    except Exception as e:
        print(f"\n[!] 系统错误: {e}")


if __name__ == "__main__":
    asyncio.run(main())
