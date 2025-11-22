import requests
from datetime import datetime, timedelta
import time

DAYS_AGO = 7
MIN_CVSS = 9.0
RATE_DELAY = 6

start_date = (datetime.now() - timedelta(days=DAYS_AGO)).strftime('%Y-%m-%dT00:00:00')
end_date = datetime.now().strftime('%Y-%m-%dT23:59:59')

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {
    'pubStartDate': start_date,
    'pubEndDate': end_date,
    'resultsPerPage': 2000,
    'startIndex': 0
}

# 用于存储符合条件的 (CVSS, CVE_ID) 对
filtered_cves = []

while True:
    try:
        resp = requests.get(url, params=params, timeout=30)
        if resp.status_code != 200:
            print(f"Request failed with status {resp.status_code}")
            break

        data = resp.json()
        for item in data.get('vulnerabilities', []):
            cve = item['cve']
            cve_id = cve['id']

            # 过滤未来年份的 CVE（如 CVE-2025-xxxx 在 2024 年出现）
            try:
                cve_year = int(cve_id.split('-')[1])
                if cve_year > datetime.now().year:
                    continue
            except (IndexError, ValueError):
                continue

            # 必须有有效英文描述，且不含 "REJECT"
            desc_valid = False
            for d in cve.get('descriptions', []):
                if d.get('lang') == 'en':
                    text = d.get('value', '')
                    if text.strip() and 'REJECT' not in text.upper():
                        desc_valid = True
                        break
            if not desc_valid:
                continue

            # 提取 CVSS 分数（优先 V3.1 → V3.0 → V2）
            cvss_score = None
            metrics = cve.get('metrics', {})
            for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if key in metrics and metrics[key]:
                    cvss_score = float(metrics[key][0]['cvssData']['baseScore'])
                    break

            # 只保留 >= MIN_CVSS 的
            if cvss_score is not None and cvss_score >= MIN_CVSS:
                filtered_cves.append((cvss_score, cve_id))

        total = data.get('totalResults', 0)
        start = data.get('startIndex', 0)
        per_page = data.get('resultsPerPage', 2000)

        if start + per_page >= total:
            break

        params['startIndex'] = start + per_page
        time.sleep(RATE_DELAY)

    except Exception as e:
        print(f"Error during fetch: {e}")
        break

# 按 CVSS 评分从高到低排序（分数相同则按 CVE ID 排序以保证稳定）
filtered_cves.sort(key=lambda x: (-x[0], x[1]))

# 输出结果
for score, cve_id in filtered_cves:
    print(f"{cve_id} (CVSS: {score})")