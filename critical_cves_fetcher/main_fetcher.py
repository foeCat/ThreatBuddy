import requests
from datetime import datetime, timedelta
import time
from typing import List, Tuple, Optional

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_RATE_DELAY = 6  # NVD API 速率限制延迟（秒）

class CriticalCVEsFetcher:
    """
    关键 CVE 提取器 - 从 NVD API 获取指定时间范围内的高 CVSS 评分漏洞
    """

    def __init__(self, rate_delay: int = DEFAULT_RATE_DELAY):
        """
        初始化提取器

        Args:
            rate_delay: API 请求之间的延迟（秒），默认 6 秒
        """
        self.rate_delay = rate_delay

    def fetch_critical_cves(self,
                          days_ago: int = 7,
                          min_cvss: float = 9.0) -> List[Tuple[float, str]]:
        """
        从 NVD API 获取指定时间范围内的关键 CVE

        Args:
            days_ago: 起始时间（天前），默认 7 天
            min_cvss: 最小 CVSS 评分，默认 9.0

        Returns:
            符合条件的 CVE 列表，格式为 (CVSS分数, CVE_ID)，按分数从高到低排序
        """
        start_date = (datetime.now() - timedelta(days=days_ago)).strftime('%Y-%m-%dT00:00:00')
        end_date = datetime.now().strftime('%Y-%m-%dT23:59:59')

        params = {
            'pubStartDate': start_date,
            'pubEndDate': end_date,
            'resultsPerPage': 2000,
            'startIndex': 0
        }

        filtered_cves = []

        while True:
            try:
                resp = requests.get(NVD_API_URL, params=params, timeout=30)
                if resp.status_code != 200:
                    print(f"[ERROR] 请求失败，状态码: {resp.status_code}", file=sys.stderr)
                    break

                data = resp.json()

                for item in data.get('vulnerabilities', []):
                    cve = item['cve']
                    cve_id = cve['id']

                    # 过滤未来年份的 CVE
                    try:
                        cve_year = int(cve_id.split('-')[1])
                        if cve_year > datetime.now().year:
                            continue
                    except (IndexError, ValueError):
                        continue

                    # 检查英文描述有效性
                    desc_valid = False
                    for d in cve.get('descriptions', []):
                        if d.get('lang') == 'en':
                            text = d.get('value', '')
                            if text.strip() and 'REJECT' not in text.upper():
                                desc_valid = True
                                break
                    if not desc_valid:
                        continue

                    # 提取 CVSS 分数（优先顺序 V3.1 → V3.0 → V2）
                    cvss_score = self._extract_cvss_score(cve)

                    # 只保留达到或超过最小 CVSS 分数的漏洞
                    if cvss_score is not None and cvss_score >= min_cvss:
                        filtered_cves.append((cvss_score, cve_id))

                # 检查是否需要分页
                total = data.get('totalResults', 0)
                current_start = data.get('startIndex', 0)
                per_page = data.get('resultsPerPage', 2000)

                if current_start + per_page >= total:
                    break

                params['startIndex'] = current_start + per_page
                time.sleep(self.rate_delay)

            except Exception as e:
                print(f"[ERROR] 请求过程中发生错误: {e}", file=sys.stderr)
                break

        # 按 CVSS 评分从高到低排序（分数相同则按 CVE ID 排序）
        filtered_cves.sort(key=lambda x: (-x[0], x[1]))
        return filtered_cves

    def _extract_cvss_score(self, cve: dict) -> Optional[float]:
        """
        从 CVE 数据中提取 CVSS 分数

        Args:
            cve: CVE 数据字典

        Returns:
            提取到的 CVSS 分数或 None
        """
        metrics = cve.get('metrics', {})

        # 按优先级顺序尝试提取 CVSS 分数
        for metric_type in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if metric_type in metrics and metrics[metric_type]:
                try:
                    return float(metrics[metric_type][0]['cvssData']['baseScore'])
                except (KeyError, ValueError, IndexError):
                    continue

        return None
