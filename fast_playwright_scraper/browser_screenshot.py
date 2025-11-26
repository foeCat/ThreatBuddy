import asyncio
import os
import random
from urllib.parse import urlparse 
import sys
from playwright.async_api import async_playwright
from playwright_stealth import Stealth


class BrowserScreenshot:
    """
    Playwright浏览器截图工具
    功能：模拟浏览器访问、截图页面
    """

    def __init__(self, headless=False):
        self.headless = headless
        self.browser = None
        self.context = None

    async def __aenter__(self):
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def initialize(self):
        """
        初始化浏览器
        """
        self.playwright = await async_playwright().start()

        # Load proxy configuration from environment variable if available
        proxy_server = os.getenv("PLAYWRIGHT_PROXY_SERVER")
        proxy_config = {"server": proxy_server} if proxy_server else None

        args = [
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-setuid-sandbox",
        ]

        self.browser = await self.playwright.chromium.launch(
            headless=self.headless,
            args=args,
            proxy=proxy_config
        )

        self.context = await self.browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        )

        await self.context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            window.chrome = { runtime: {} };
            window.outerWidth = 1920;
            window.outerHeight = 1080;
            Object.defineProperty(navigator, 'appVersion', {
                get: () => '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
            });
            window.screen.width = 1920;
            window.screen.height = 1080;
            window.screen.colorDepth = 24;
            window.screen.pixelDepth = 24;
        """)

    async def close(self):
        if hasattr(self, 'context') and self.context:
            await self.context.close()
        if hasattr(self, 'browser') and self.browser:
            await self.browser.close()
        if hasattr(self, 'playwright') and self.playwright:
            await self.playwright.stop()

    async def simulate_human_behavior(self, page):
        await page.wait_for_timeout(random.randint(300, 800))
        await page.mouse.move(random.randint(300, 800), random.randint(200, 500))
        await page.evaluate("window.scrollBy(0, window.innerHeight / 3)")
        await page.wait_for_timeout(random.randint(200, 500))

    async def screenshot_page(self, url, output_dir="screenshots", filename=None):
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        if "nvd.nist.gov" in netloc or "zhihu.com" in netloc:
            print(f"skip: {url}", file=sys.stderr)
            return None, None
        
        page = await self.context.new_page()

        try:
            await Stealth().apply_stealth_async(page)

            await page.set_extra_http_headers({
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "DNT": "1",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
            })

            # 访问页面（允许跳转开始）
            await page.goto(url, wait_until="commit", timeout=60000)

            # 等待页面基本加载完成
            try:
                await page.wait_for_function("() => document.readyState === 'complete'", timeout=10000)
            except Exception:
                pass  # 不中断流程

            # 👇 关键：如果当前是 Bing 跳转中间页，等待跳出去
            if "bing.com/ck/" in page.url:
                print(f"检测到 Bing 跳转页，正在等待跳转...")
                try:
                    await page.wait_for_url(lambda u: "bing.com/ck/" not in u, timeout=15000)
                    print(f"已跳转至: {page.url}")
                except Exception:
                    print("⚠️ 跳转超时，可能仍在中间页")
            final_netloc = urlparse(page.url).netloc.lower()
            if "nvd.nist.gov" in final_netloc or "zhihu.com" in final_netloc:
                print(f"skip after redirect: {page.url}", file=sys.stderr)
                return None, None

            # 模拟人类行为
            await self.simulate_human_behavior(page)

            # 截图
            screenshot_bytes = await page.screenshot(full_page=True)

            save_path = None
            if output_dir and filename:
                os.makedirs(output_dir, exist_ok=True)
                save_path = os.path.join(output_dir, filename)
                with open(save_path, "wb") as f:
                    f.write(screenshot_bytes)

            return screenshot_bytes, save_path

        finally:
            await page.close()

    async def search_bing(self, query, max_results=20):
        page = await self.context.new_page()

        try:
            await Stealth().apply_stealth_async(page)

            await page.set_extra_http_headers({
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "DNT": "1",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
            })

            search_url = f"https://www.bing.com/search?q={query.replace(' ', '+')}"
            print(f"正在访问: {search_url}")

            await page.goto(search_url, wait_until="load", timeout=30000)
            await page.wait_for_timeout(2000)

            links = []
            for el in await page.query_selector_all("ol#b_results li.b_algo h2 a"):
                href = await el.get_attribute("href")
                if href and href.startswith("http") and "zhihu.com" not in href and "nvd.nist.gov" not in href:
                    links.append(href)
                    if len(links) >= max_results:
                        break
            return links

        finally:
            await page.close()


async def main():
    import sys
    if len(sys.argv) < 2:
        print("Browser Screenshot模块 - 可以独立运行")
        print("使用方法：")
        print("1. 将本模块导入其他脚本")
        print("2. 或者直接运行测试：python browser_screenshot.py <url>")
        return

    url = sys.argv[1]
    print(f"正在访问页面: {url}")

    async with BrowserScreenshot(headless=False) as browser:  # 可设 headless=True 无界面
        screenshot_bytes, save_path = await browser.screenshot_page(url, filename="test_screenshot.png")
        if save_path:
            print(f"截图已保存至: {save_path}")
            print(f"截图大小: {len(screenshot_bytes)} bytes")
        else:
            print(f"截图已获取，大小: {len(screenshot_bytes)} bytes")


if __name__ == "__main__":
    asyncio.run(main())