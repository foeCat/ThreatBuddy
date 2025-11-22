from cve_scraper.config import SEARCH_QUERY

async def get_search_links(browser, page_creator, max_sources):
    """Get search result links from Bing"""
    print(f"Searching Bing for: {SEARCH_QUERY}")

    page = await page_creator(browser)
    try:
        await page.goto(f"https://www.bing.com/search?q={SEARCH_QUERY}", timeout=30000)
        await page.wait_for_selector("ol#b_results", state="attached", timeout=15000)

        # Extract links
        links = await page.eval_on_selector_all(
            "ol#b_results li.b_algo h2 a",
            "els => els.map(el => el.href).filter(href => href?.startsWith('http'))"
        )

        selected_links = links[:max_sources]
        print(f"Found {len(links)} links, processing {len(selected_links)}")
        return selected_links
    finally:
        await page.close()
