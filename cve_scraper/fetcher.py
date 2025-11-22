import asyncio
from cve_scraper.config import CVE_ID
from cve_scraper.utils import truncate, divider


async def fetch_content(page, url: str, index: int):
    """
    Fetch content from a single URL (generic sites).
    Now returns the full raw HTML after rendering.

    Returns:
        dict or None: {
            "url": str,
            "html": str,      # FULL raw HTML
            "text": str,      # Full visible text
            "source": "generic"
        }
    """
    print(f"\nProcessing result {index}: {url}")

    try:
        await page.goto(url, timeout=30000, wait_until="domcontentloaded")

        # Wait for relevant content (with timeout)
        try:
            await page.wait_for_function(
                f"""
                () => {{
                    const text = document.body.innerText;
                    return text.includes('{CVE_ID}') ||
                           text.toLowerCase().includes('vulnerability') ||
                           text.toLowerCase().includes('exploit');
                }}
                """,
                timeout=20000
            )
            print("✓ Found relevant content")
        except Exception:
            print("? No relevant content detected, continuing")

        # Optional: wait for JS to settle
        await asyncio.sleep(3)

        # === GET FULL CONTENT ===
        full_html = await page.content()  # Full raw HTML
        visible_text = await page.eval_on_selector("body", "el => el.innerText")

        # === PRINT FULL HTML AND TEXT ===
        divider()
        # print(f"Page {index} Full HTML content:")
        # print(f"URL: {url}")
        # divider()
        # print(full_html)  # Output full HTML instead of snippet

        # print("\nFull visible text:")
        # print(visible_text)  # Output full text instead of snippet
        divider()
        print()

        # === RETURN FULL DATA ===
        return {
            "url": url,
            "html": full_html,
            "text": visible_text,
            "source": "generic"
        }

    except Exception as e:
        error_msg = f"✗ Failed to fetch {url}: {str(e)}"
        print(error_msg[:150])
        return None
