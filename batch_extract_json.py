#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path

EXTRACT_SCRIPT = Path("cve_intel_extractor/run_extractor.py")
CVE_LIST_FILE = Path("scraped_data/cve_lists/latest_cves.txt")

def main():
    if not EXTRACT_SCRIPT.is_file():
        print(f"missing: {EXTRACT_SCRIPT}", file=sys.stderr)
        sys.exit(1)
    if not CVE_LIST_FILE.is_file():
        print(f"missing: {CVE_LIST_FILE}", file=sys.stderr)
        sys.exit(1)

    with open(CVE_LIST_FILE) as f:
        cves = [line.strip() for line in f if line.strip()]

    for cve in cves:
        try:
            subprocess.run([sys.executable, str(EXTRACT_SCRIPT), cve], check=True)
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception:
            print(f"{cve} failed", file=sys.stderr)

if __name__ == "__main__":
    main()