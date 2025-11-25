import asyncio
import os
import re
import sys
import random
from .browser_screenshot import BrowserScreenshot
from .ocr_processor import OCRProcessor


class CVEOCREngine:
    """
    CVE OCR引擎
    功能：整合浏览器搜索、截图和OCR识别功能
    """

    def __init__(self):
        self.browser = None
        self.ocr_processor = OCRProcessor()

    async def process_cve(self, cve_id, max_links=20, max_results=3):
        """
        处理指定CVE ID
        :param cve_id: CVE ID
        :param max_links: 最多搜索结果链接数
        :param max_results: 最多返回的OCR结果数
        :return: 包含源URL和识别文本的结果列表
        """
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id.strip().upper()):
            raise ValueError("无效的CVE ID格式，应为CVE-XXXX-XXXXX")

        cve_id = cve_id.strip().upper()
        results = []

        async with BrowserScreenshot() as browser:
            # 搜索CVE
            search_query = cve_id
            links = await browser.search_bing(search_query, max_results=max_links)

            for url in links:
                if len(results) >= max_results:
                    break

                try:
                    # 截图页面
                    clean_url = re.sub(r"https?://", "", url.split("?")[0])
                    clean_url = re.sub(r"[^\w\-_.]", "_", clean_url)[:80]
                    filename = f"{cve_id}__{clean_url}.png"

                    screenshot_bytes, _ = await browser.screenshot_page(
                        url,
                        output_dir="screenshots",
                        filename=filename
                    )

                    # OCR识别
                    ocr_text = self.ocr_processor.ocr_image(screenshot_bytes, cve_id)

                    if ocr_text:
                        results.append({
                            "source": url,
                            "text": ocr_text
                        })

                    # 随机等待2-5秒作为请求间隔
                    await asyncio.sleep(random.randint(2, 5))

                except Exception:
                    continue

        return results

    async def process_cve_and_save(self, cve_id, output_file=None):
        """
        处理CVE并保存结果到文件
        :param cve_id: CVE ID
        :param output_file: 输出文件名，None则自动生成
        """
        results = await self.process_cve(cve_id)

        if not results:
            print(f"未找到与CVE ID: {cve_id}相关的有效信息")
            return False

        # 生成输出文件名
        if not output_file:
            output_file = f"{cve_id}.txt"

        # 写入结果
        with open(output_file, "w", encoding="utf-8") as f:
            for result in results:
                f.write(f"{'='*60}\n")
                f.write(f"Source: {result['source']}\n")
                f.write(f"{'='*60}\n")
                f.write(f"{result['text']}\n\n")

        print(f"处理完成，结果已保存至: {output_file}")
        return True


async def main():
    """
    主函数
    """
    if len(sys.argv) != 2 or not re.match(r"^CVE-\d{4}-\d{4,}$", sys.argv[1].strip().upper()):
        print("用法: python -m fast_playwright_scraper.main_ocr CVE-XXXX-XXXXX")
        sys.exit(1)

    cve_id = sys.argv[1].strip().upper()
    engine = CVEOCREngine()
    await engine.process_cve_and_save(cve_id)


if __name__ == "__main__":
    asyncio.run(main())