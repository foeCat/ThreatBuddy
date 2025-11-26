#!/usr/bin/env python3
"""
CVE OCR运行脚本 - 直接执行版
"""
import asyncio
from pathlib import Path
import re
import sys
import random
from browser_screenshot import BrowserScreenshot
from ocr_processor import OCRProcessor


async def main():
    if len(sys.argv) != 2 or not re.match(r"^CVE-\d{4}-\d{4,}$", sys.argv[1].strip().upper()):
        print("用法: python run_cve_ocr.py CVE-XXXX-XXXXX")
        print("例如: python run_cve_ocr.py CVE-2025-41115")
        sys.exit(1)

    cve_id = sys.argv[1].strip().upper()
    max_links = 20
    max_results = 3

    ocr_processor = OCRProcessor()
    results = []

    print(f"正在处理CVE ID: {cve_id}")
    print("=" * 60)

    async with BrowserScreenshot() as browser:
        # 搜索CVE
        print(f"正在搜索: {cve_id}")
        links = await browser.search_bing(cve_id, max_results=max_links)
        print(f"找到 {len(links)} 个搜索结果")

        for idx, url in enumerate(links, 1):
            if len(results) >= max_results:
                break

            print(f"\n[{idx}/{len(links)}] 正在处理: {url}")

            try:
                # 截图页面
                screenshot_bytes, _ = await browser.screenshot_page(url)

                # OCR识别
                ocr_text = ocr_processor.ocr_image(screenshot_bytes, cve_id)

                if ocr_text:
                    results.append({
                        "source": url,
                        "text": ocr_text
                    })
                    print(f"✓ 成功识别并验证CVE")

                # 随机等待1-3秒作为请求间隔
                await asyncio.sleep(random.randint(1, 3))

            except Exception as e:
                print(f"✗ 处理失败: {e}")
                continue

    print("\n" + "=" * 60)
    if results:
        # 保存结果
        output_dir = Path(__file__).parent.parent / "scraped_data"
        output_file = output_dir / f"{cve_id}.txt"
        with open(output_file, "w", encoding="utf-8") as f:
            for result in results:
                f.write(f"{'='*60}\n")
                f.write(f"Source: {result['source']}\n")
                f.write(f"{'='*60}\n")
                f.write(f"{result['text']}\n\n")

        print(f"处理完成！")
        print(f"成功识别 {len(results)} 个有效结果")
        print(f"结果已保存至: {output_file}")
    else:
        print("未找到与该CVE相关的有效信息")


if __name__ == "__main__":
    asyncio.run(main())