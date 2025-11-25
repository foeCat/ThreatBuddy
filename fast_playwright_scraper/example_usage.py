#!/usr/bin/env python3
"""
模块使用示例
展示如何独立使用各个解耦的模块
"""
import asyncio


async def example_browser_screenshot():
    """
    示例：使用浏览器截图模块
    """
    from browser_screenshot import BrowserScreenshot

    async with BrowserScreenshot() as browser:
        # 1. 搜索Bing
        # links = await browser.search_bing("CVE-2025-41115", max_results=5)
        # print(f"搜索结果: {links}")

        # 2. 截图页面
        url = "https://www.example.com"
        screenshot_bytes, save_path = await browser.screenshot_page(
            url,
            filename="example_screenshot.png"
        )
        if save_path:
            print(f"页面截图已保存至: {save_path}")


async def example_ocr_processor():
    """
    示例：使用OCR处理器模块
    """
    from ocr_processor import OCRProcessor

    processor = OCRProcessor()

    # 示例图像路径
    # image_path = "screenshots/test.png"
    # result = processor.ocr_image_file(image_path, cve_id="CVE-2025-41115")
    # if result:
    #     print(f"OCR识别结果: {result[:50]}...")


async def example_full_pipeline():
    """
    示例：使用完整的CVE OCR流程
    """
    from main_ocr import CVEOCREngine

    engine = CVEOCREngine()

    # 处理CVE并保存结果
    # success = await engine.process_cve_and_save("CVE-2025-41115")
    # print(f"处理结果: {'成功' if success else '失败'}")


async def main():
    print("CVE OCR模块示例")
    print("=" * 40)

    print("\n1. 浏览器截图示例 (已注释)")
    # await example_browser_screenshot()

    print("\n2. OCR处理器示例 (已注释)")
    # await example_ocr_processor()

    print("\n3. 完整流程示例 (已注释)")
    # await example_full_pipeline()

    print("\n要运行示例，请取消对应函数的注释")
    print("\n或者直接运行 run_cve_ocr.py 脚本：")
    print("  python run_cve_ocr.py CVE-2025-41115")


if __name__ == "__main__":
    asyncio.run(main())