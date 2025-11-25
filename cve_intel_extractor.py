import requests
import json
import sys
from typing import Optional

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_cve_intel(cve_id: str) -> Optional[dict]:
    if not (isinstance(cve_id, str) and cve_id.upper().startswith("CVE-")):
        return None

    try:
        resp = requests.get(
            f"{NVD_API_URL}?cveId={cve_id.upper()}",
            headers={"User-Agent": "ThreatIntel/1.0"},
            timeout=10
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        vulns = data.get("vulnerabilities")
        if not vulns:
            return None
        cve = vulns[0]["cve"]
    except Exception:
        return None

    description_en = next(
        (d["value"].strip() for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        next((d["value"].strip() for d in cve.get("descriptions", [])), "")
    )

    cvss_v31 = {}
    metrics = cve.get("metrics")
    if metrics:
        m31 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
        if m31:
            base = m31[0]["cvssData"]
            cvss_v31 = {
                "score": base.get("baseScore"),
                "severity": base.get("baseSeverity"),
                "vector": base.get("vectorString")
            }

    cvss_v2 = {}
    if metrics and metrics.get("cvssMetricV2"):
        base = metrics["cvssMetricV2"][0]["cvssData"]
        cvss_v2 = {
            "score": base.get("baseScore"),
            "severity": metrics["cvssMetricV2"][0].get("baseSeverity"),
            "vector": base.get("vectorString")
        }

    cwe_ids = [
        desc["value"]
        for w in cve.get("weaknesses", [])
        for desc in w.get("description", [])
        if desc.get("value") not in ("NVD-CWE-noinfo", "NVD-CWE-Other")
    ]

    affected_cpes = []
    for config in cve.get("configurations", []):
        nodes = config.get("nodes", [config])
        for node in nodes:
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") is True:
                    crit = match.get("criteria")
                    if crit and crit not in affected_cpes:
                        affected_cpes.append(crit)

    seen = set()
    references = []
    for ref in cve.get("references", []):
        url = ref.get("url")
        if url and url not in seen:
            seen.add(url)
            references.append({"url": url, "tags": ref.get("tags", [])})

    vendor_comments = [cmt["comment"] for cmt in cve.get("vendorComments", [])]

    kev_date = cve.get("cisaExploitAdd")
    in_kev = kev_date is not None

    cve_tags = []
    for tag in cve.get("cveTags", []):
        if isinstance(tag, dict):
            # Try different key names that might contain the tag value
            cve_tags.append(tag.get("value", tag.get("name", tag.get("tag", ""))))
        else:
            cve_tags.append(str(tag))
    cve_tags = [tag for tag in cve_tags if tag]

    return {
        "id": cve.get("id"),
        "source_identifier": cve.get("sourceIdentifier"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "description_en": description_en,
        "cvss_v31": cvss_v31,
        "cvss_v2": cvss_v2,
        "cwe_ids": cwe_ids,
        "affected_cpes": affected_cpes,
        "references": references,
        "vendor_comments": vendor_comments,
        "in_kev": in_kev,
        "kev_date": kev_date,
        "kev_action_due": cve.get("cisaActionDue"),
        "kev_required_action": cve.get("cisaRequiredAction"),
        "cve_tags": cve_tags
    }

# ========================
# CLI 入口（仅当直接运行脚本时生效）
# ========================
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python cve_intel_extractor.py CVE-XXXX-XXXXX", file=sys.stderr)
        sys.exit(1)

    cve_id = sys.argv[1].strip()
    intel = fetch_cve_intel(cve_id)

    if intel is None:
        print("null")
        sys.exit(1)
    else:
        output_json = json.dumps(intel, ensure_ascii=False, separators=(',', ':'))
        print(output_json)  # 仍输出到 stdout

        # 🌟 新增：保存到本地文件
        filename = f"scraped_data/{cve_id.upper()}.json"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(output_json)
        print(f"[+] 已保存原始情报到: {filename}", file=sys.stderr)