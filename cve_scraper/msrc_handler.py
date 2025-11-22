"""MSRC (Microsoft Security Response Center) page handler"""

async def fetch_msrc_content(page, url, index):
    """
    Fetch content from MSRC pages and return full HTML.
    Maintains consistent return structure with fetch_content.

    Returns:
        dict or None: {
            "url": str,
            "html": str,      # FULL raw HTML
            "text": str,      # Full visible text (optional for MSRC, but included for consistency)
            "source": "msrc"
        }
    """
    print(f"\nProcessing MSRC result {index}: {url}")

    try:
        await page.goto(url, timeout=60000, wait_until="domcontentloaded")

        # MSRC pages are dynamic, wait for content
        await page.wait_for_selector("body", state="attached", timeout=30000)

        # Wait for JavaScript to fully render
        await page.wait_for_timeout(5000)

        # Get full HTML and text content
        html = await page.content()
        text = await page.eval_on_selector("body", "el => el.innerText")

        print(f"✓ Successfully fetched full MSRC page")

        # Return consistent structure with generic fetcher
        return {
            "url": url,
            "html": html,
            "text": text,
            "source": "msrc"
        }

    except Exception as e:
        print(f"✗ Failed to fetch MSRC page {url}: {str(e)[:150]}")
        return None
