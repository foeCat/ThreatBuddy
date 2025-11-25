# generate_threat_intel.py
import json
import os
from typing import Optional, Dict, Any
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnableLambda

DATA_DIR = "/home/arldev/scraped_data"

# Load .env file
load_dotenv()

def load_nvd_data(cve_id: str) -> Optional[Dict[str, Any]]:
    """加载 NVD 原始 JSON 数据"""
    filename = os.path.join(DATA_DIR, f"{cve_id}.json")
    if not os.path.exists(filename):
        print(f"[!] 未找到 NVD 文件: {filename}")
        return None
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] 加载 NVD 文件失败: {e}")
        return None

def load_web_data(cve_id: str) -> Optional[str]:
    """加载 Web 搜索摘要文本"""
    filename = os.path.join(DATA_DIR, f"{cve_id}.txt")
    if not os.path.exists(filename):
        print(f"[!] 未找到 Web 情报文件: {filename}")
        return ""
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        print(f"[!] 加载 Web 文件失败: {e}")
        return ""

def create_intel_prompt(nvd_data: Dict[str, Any], web_content: str) -> str:
    """构建提示词模板，优先使用 NVD 数据，Web 补充"""
    # 提取关键字段
    cve_id = nvd_data.get("id", "UNKNOWN")
    published = nvd_data.get("published", "")
    description_en = nvd_data.get("description_en", "")
    cvss_v31 = nvd_data.get("cvss_v31", {})
    severity = cvss_v31.get("severity", "Unknown")
    vector = cvss_v31.get("vector", "")
    cwe_ids = nvd_data.get("cwe_ids", [])
    references = nvd_data.get("references", [])
    official_url = next((r["url"] for r in references if r.get("tags") and "Official" in r["tags"]), "")

    # 构建 prompt
    prompt_text = f"""
你是一名资深网络安全威胁情报分析师，请根据以下两份资料，撰写一份高质量、可用于企业安全运营的中文威胁情报报告。

=== 主要信息源：NVD 官方数据 ===
CVE ID: {cve_id}
披露时间: {published}
描述 (英文): {description_en}
CVSS v3.1: {severity} ({vector})
CWE 编号: {', '.join(cwe_ids)}
官方公告链接: {official_url}

=== 补充信息源：Web 搜索摘要 ===
{web_content}

=== 输出要求 ===
1. 使用 Markdown 格式输出
2. 严格遵循以下模板结构（必须使用相同的标题级别和格式）：
   - # [{cve_id}] 漏洞名称
   - 发布时间：YYYY-MM-DD

   - ## 一、漏洞概述
     (用表格形式展示漏洞基本信息：漏洞名称、CVE ID、漏洞类型、发现时间、公开时间、漏洞评分、漏洞等级、攻击向量、所需权限、利用难度、用户交互、PoC/EXP状态、在野利用状态等)

   - ## 二、漏洞详情
     ### 2.1 影响组件
     (描述受影响的组件/产品)

     ### 2.2 漏洞描述
     (详细描述漏洞的技术原理和根本原因)

   - ## 三、影响范围
     ### 3.1 影响版本
     (列出受影响的具体版本范围，使用<=, >=等符号)

   - ## 四、处置建议
     ### 4.1 安全更新
     (官方修复版本信息及下载地址)

     ### 4.2 临时措施
     (无法立即升级时的临时缓解方法)

     ### 4.3 安全建议
     (针对安全团队的行动建议)

   - ## 五、参考资料
     (列出相关参考链接，如官方公告、CISA 预警等)

3. 内容必须忠实于原始数据，可适当整合 Web 搜索信息补充细节（如 PoC、在野利用、厂商建议）
4. 使用专业术语，避免冗余解释
5. 若某项信息未提及，可省略该内容或小节，无需标注“未提及”
6. 表格应使用 Markdown 表格格式，确保清晰易读
7. 最终输出应可直接发布至内部 Wiki 或安全通告系统
"""

    return prompt_text

def generate_md_report(cve_id: str) -> str:
    """主函数：生成 Markdown 报告"""
    # 加载数据
    nvd_data = load_nvd_data(cve_id)
    if not nvd_data:
        return "# 错误：无法获取 NVD 数据\n\n[NVD 数据缺失]\n"

    web_content = load_web_data(cve_id)

    # 构建提示词
    prompt_text = create_intel_prompt(nvd_data, web_content)

    # 初始化 LLM（使用 DeepSeek via ChatOpenAI interface）
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return "# 错误：API 密钥缺失\n\n[未在 .env 文件中找到 OPENAI_API_KEY]\n"

    llm = ChatOpenAI(
        model="deepseek-chat",
        api_key=api_key,
        base_url="https://api.deepseek.com",
        temperature=0.7
    )

    try:
        from langchain_core.messages import HumanMessage
        response = llm.invoke([HumanMessage(content=prompt_text)])
        return response.content.strip()
    except Exception as e:
        return f"# 错误：LLM 调用失败\n\n{str(e)}"

# ========================
# CLI 入口
# ========================
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python generate_threat_intel.py CVE-XXXX-XXXXX", file=sys.stderr)
        sys.exit(1)

    cve_id = sys.argv[1].strip()
    report = generate_md_report(cve_id)

    # 输出到终端和文件
    output_file = f"{cve_id}_intel_summary.md"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"[+] 已生成报告: {output_file}")
    print("\n" + "="*50)
    print(report)