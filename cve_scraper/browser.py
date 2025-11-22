from playwright.async_api import async_playwright
from playwright_stealth import Stealth

async def create_browser():
    """Create a browser instance"""
    args = [
        "--disable-blink-features=AutomationControlled",
        "--no-sandbox",
        "--disable-setuid-sandbox",
    ]

    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch(headless=True, args=args)
    return browser, playwright

async def create_page(browser):
    """Create a stealth page with basic anti-detection"""
    page = await browser.new_page()

    # Apply playwright-stealth
    await Stealth().apply_stealth_async(page)

    # Set normal headers
    await page.set_extra_http_headers({
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    })

    return page
