# ThreatBuddy: 自动化威胁情报生成系统

ThreatBuddy是一个自动化的威胁情报生成系统，能够批量收集、分析和生成CVE漏洞的威胁情报报告。系统集成了多源数据抓取、NVD API查询、文本信息提取和AI驱动的报告生成功能。

## ✨ 核心功能

- **CVE数据自动获取**: 多源CVE数据抓取与自动缓存
- **NVD信息整合**: 权威的CVE漏洞详情获取
- **AI驱动分析**: 智能的漏洞信息提取与摘要
- **自动化报告生成**: 结构化Markdown威胁情报报告
- **批量处理**: 支持大规模CVE数据处理

## 🚀 快速开始

### 1. 环境配置
```bash
# 配置API Key
cp .env.example .env
# 编辑.env文件，填入有效的OpenAI API Key

# 安装Python依赖
pip install playwright python-dotenv requests
# 安装Playwright浏览器
playwright install
# 安装OCR引擎依赖
pip install pytesseract
# 安装系统OCR库 (Debian/Ubuntu)
sudo apt-get install tesseract-ocr
# 安装系统OCR库 (CentOS)
# sudo yum install tesseract
```

### 2. 运行系统
#### 完整自动化流程
```bash
python automated_threat_intel.py
```

#### 批量生成报告
```bash
python batch_generate_reports.py
```

#### 单个CVE处理
```bash
python fast_playwright_scraper/run_cve_ocr.py CVE-2025-10437
python threat_intel_generator/run_generator.py CVE-2025-10437
```

## 🎯 主要脚本说明

| 脚本文件 | 功能 |
|---------|------|
| automated_threat_intel.py | 主自动化流程脚本 |
| batch_generate_reports.py | 批量报告生成 |
| fast_playwright_scraper/run_cve_ocr.py | 网页CVE数据抓取 |
| cve_intel_extractor/run_extractor.py | CVE权威信息获取 |
| threat_intel_generator/run_generator.py | AI报告生成 |

## 📦 输出

- **scraped_data/目录**: CVE数据文件 (.json, .txt)
- **results/目录**: 生成的Markdown报告 (.md)

## 📝 注意事项

1. 确保拥有有效的OpenAI API Key
2. 首次运行需要安装Playwright浏览器
3. 需要安装Tesseract OCR引擎
4. 确保网络访问正常

## 📄 许可证

MIT License
