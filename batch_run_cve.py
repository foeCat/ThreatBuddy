#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path

RUN_SCRIPT = Path("fast_playwright_scraper/run_cve_ocr.py")
CVE_LIST_FILE = Path("scraped_data/cve_lists/latest_cves.txt")

def main():
    if not RUN_SCRIPT.exists():
        print(f"missing: {RUN_SCRIPT}", file=sys.stderr)
        sys.exit(1)
    if not CVE_LIST_FILE.exists():
        print(f"missing: {CVE_LIST_FILE}", file=sys.stderr)
        sys.exit(1)

    with open(CVE_LIST_FILE) as f:
        cves = [line.strip() for line in f if line.strip()]

    print(f"start: {len(cves)} CVEs", file=sys.stderr)

    for cve in cves:
        try:
            subprocess.run([sys.executable, str(RUN_SCRIPT), cve], check=True, stdout=subprocess.DEVNULL)
        except KeyboardInterrupt:
            sys.exit(0)
        except:
            print(f"{cve} failed", file=sys.stderr)

if __name__ == "__main__":
    main()