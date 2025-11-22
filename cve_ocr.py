import asyncio
import io
import os
import re
import sys
import random
from PIL import Image
from playwright.async_api import async_playwright
from playwright_stealth import Stealth, StealthConfig
import pytesseract


async def simulate_human_behavior(page):
    """模拟人类浏览行为"""
    # 随机等待1-3秒
    await page.wait_for_timeout(random.randint(1500, 3000))

    # 模拟鼠标移动
    await page.mouse.move(random.randint(300, 800), random.randint(200, 500))

    # 滚动页面
    await page.evaluate("window.scrollBy(0, window.innerHeight / 3)")

    # 再次随机等待0.5-1秒
    await page.wait_for_timeout(random.randint(500, 1000))


async def _ocr_page(page, url: str, cve_id: str) -> str | None:
    try:
        await page.goto(url, wait_until="networkidle", timeout=30000)
        title = await page.title()
        if any(kw in title.lower() for kw in ["just a moment", "checking your browser", "access denied", "captcha"]):
            return None
        if await page.evaluate("document.body.innerText.length") < 50:
            return None

        screenshot = await page.screenshot(full_page=True)

        os.makedirs("screenshots", exist_ok=True)
        clean = re.sub(r"https?://", "", url.split("?")[0])
        clean = re.sub(r"[^\w\-_.]", "_", clean)[:80]
        path = f"screenshots/{cve_id}__{clean}.png"
        with open(path, "wb") as f:
            f.write(screenshot)

        img = Image.open(io.BytesIO(screenshot)).convert('L')
        img = img.point(lambda x: 255 if x > 128 else 0, mode='1')
        text = pytesseract.image_to_string(img, lang='eng').strip()

        pattern = r"\b" + re.escape(cve_id) + r"\b"
        return text if re.search(pattern, text, re.IGNORECASE) else None

    except Exception:
        return None


async def main(cve_id: str):
    search_url = f"https://www.bing.com/search?q={cve_id.replace(' ', '+')}"

    async with async_playwright() as p:
        # Launch browser with anti-detection arguments
        args = [
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-setuid-sandbox",
        ]

        browser = await p.chromium.launch(headless=True, args=args)
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        )
        await context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")

        page = await context.new_page()

        # Apply playwright-stealth to avoid detection
        await Stealth().apply_stealth_async(page)

        # Set normal headers
        await page.set_extra_http_headers({
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        })

        await page.goto(search_url, wait_until="networkidle", timeout=20000)

        links = []
        for el in await page.query_selector_all("ol#b_results li.b_algo h2 a"):
            href = await el.get_attribute("href")
            if href and href.startswith("http"):
                links.append(href)
                if len(links) >= 20:
                    break

        results = []
        detail_page = await context.new_page()

        # Apply playwright-stealth to detail page
        await Stealth().apply_stealth_async(detail_page)

        # Set normal headers for detail page
        await detail_page.set_extra_http_headers({
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        })

        for url in links:
            if len(results) >= 4:
                break
            text = await _ocr_page(detail_page, url, cve_id)
            if text:
                results.append(f"{'='*60}\nSource: {url}\n{'='*60}\n{text}\n\n")

        await browser.close()

        if results:
            with open(f"{cve_id}.txt", "w", encoding="utf-8") as f:
                f.write("\n".join(results))


if __name__ == "__main__":
    if len(sys.argv) != 2 or not re.match(r"^CVE-\d{4}-\d{4,}$", sys.argv[1].strip().upper()):
        print("用法: python script.py CVE-XXXX-XXXXX")
        sys.exit(1)
    asyncio.run(main(sys.argv[1].strip().upper()))