"""
Critical CVE Fetcher 模块
用于从 NVD API 获取指定时间范围内的高 CVSS 评分漏洞
"""

from .main_fetcher import CriticalCVEsFetcher

__version__ = "0.1.0"
__all__ = [
    "CriticalCVEsFetcher"
]
