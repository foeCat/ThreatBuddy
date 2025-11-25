# 各个脚本功能定位

## fetch_critical_cves.py
- 用途：**批量**获取最近7天内CVSS评分≥9.0的高危CVE列表
- 输入：无参数（配置在脚本内部）
- 输出：标准输出显示过滤后的CVE列表

## fast_playwright_scraper/run_cve_ocr.py
- 用途：处理**单个**CVE，通过Bing搜索并使用OCR识别相关网页内容
- 输入：单个CVE-ID参数
- 输出：保存识别结果到 `scraped_data/<CVE-ID>.txt`

## web_txt_to_intel.py
- 用途：处理**单个**CVE的OCR结果，使用LLM提取专业威胁情报
- 输入：单个CVE-ID参数
- 输出：修改 `scraped_data/<CVE-ID>.txt` 文件，替换为精简后的威胁情报

## cve_intel_extractor.py
- 用途：处理**单个**CVE，从NVD API获取详细的技术数据
- 输入：单个CVE-ID参数
- 输出：保存JSON数据到 `scraped_data/<CVE-ID>.json`

## generate_threat_intel.py
- 用途：处理**单个**CVE，结合OCR结果和NVD数据生成专业的MD格式威胁情报
- 输入：单个CVE-ID参数
- 输出：返回MD格式的威胁情报字符串

## main.py
- 用途：自动化处理**批量**高危CVE，集成所有脚本功能
