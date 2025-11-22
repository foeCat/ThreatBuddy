import asyncio
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cve_scraper.config import CVE_ID, MAX_SOURCES
from cve_scraper.browser import create_browser, create_page
from cve_scraper.search import get_search_links
from cve_scraper.fetcher import fetch_content
from cve_scraper.msrc_handler import fetch_msrc_content

async def main():
    print(f"\nStarting CVE data collection for: {CVE_ID}\n")

    browser, playwright = await create_browser()
    try:
        # Get search links
        links = await get_search_links(browser, create_page, MAX_SOURCES)

        # Fetch content from each link
        for index, url in enumerate(links, 1):
            page = await create_page(browser)
            try:
                if "msrc.microsoft.com" in url:
                    # Handle MSRC pages specially to get full HTML
                    result = await fetch_msrc_content(page, url, index)
                    if result:
                        # Save full HTML to file
                        filename = f"msrc_result_{index}.html"
                        with open(filename, "w", encoding="utf-8") as f:
                            f.write(result["html"])
                        print(f"✓ Saved complete MSRC content to {filename}")
                else:
                    # Use original non-intrusive fetcher for other pages
                    result = await fetch_content(page, url, index)
                    if result:
                        # Save full HTML to file
                        filename = f"generic_result_{index}.html"
                        with open(filename, "w", encoding="utf-8") as f:
                            f.write(result["html"])
                        print(f"✓ Saved complete generic content to {filename}")
            finally:
                await page.close()

        print("\nCollection completed.")

    finally:
        await browser.close()
        await playwright.stop()

if __name__ == "__main__":
    asyncio.run(main())
