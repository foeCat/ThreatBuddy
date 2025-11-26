#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web TXT Intel Extractor - Main functionality module
从本地 .txt 文件中提取专业级威胁情报摘要。
直接单次调用 DeepSeek LLM，不分块，输出高保真纯文本报告。
"""

import sys
import os
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI


class WebTxtIntelExtractor:
    """
    Web TXT Intel Extractor - Extract threat intelligence from local txt files.
    """

    def __init__(self, scraped_data_dir: str = "./scraped_data/"):
        """
        Initialize the WebTxtIntelExtractor.

        Args:
            scraped_data_dir: Directory path where scraped txt files are stored
        """
        self.scraped_data_dir = scraped_data_dir

        # 🔑 API Key
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("[!] 错误：未在 .env 中找到 OPENAI_API_KEY")

        # 使用 deepseek-chat（非思考模式），限制 max_tokens 提升效率
        self.llm = ChatOpenAI(
            model="deepseek-chat",
            api_key=self.api_key,
            base_url="https://api.deepseek.com",
            temperature=0.0,
            max_tokens=2048,  # 足够容纳详细摘要，避免冗余
        )

    def read_txt_file(self, cve_id: str) -> str:
        """
        Read content from a local txt file.

        Args:
            cve_id: CVE ID to read file for

        Returns:
            str: Content of the file or empty string if read fails
        """
        txt_path = Path(f"{self.scraped_data_dir}/{cve_id}.txt")
        if not txt_path.exists():
            print(f"[!] 文件不存在: {txt_path}", file=sys.stderr)
            return ""
        try:
            return txt_path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"[!] 读取文件失败: {e}", file=sys.stderr)
            return ""

    async def extract_summary(self, text: str, cve_id: str) -> str:
        """
        Extract threat intelligence summary from text using LLM.

        Args:
            text: Raw text to process
            cve_id: CVE ID for this text

        Returns:
            str: Extracted summary
        """
        if not text.strip():
            return "错误：输入内容为空。"

        # 🌟 关键改进：使用更专业的开放式 prompt
        prompt = ChatPromptTemplate.from_messages([
            ("system", """
你是一名资深威胁情报分析师，任务是从原始技术文本中提取高保真、可操作的威胁情报。

请基于以下原始内容，撰写一份专业、详实、结构清晰的中文威胁情报摘要。要求如下：

1. 输出必须为纯文本，禁止使用 JSON、Markdown、XML 或任何格式标记；
2. 以“{cve_id} 威胁情报摘要（纯文本格式）”开头；尽量包含专业性的代码或者英文词汇
3. 内容应逻辑清晰、层次分明，可通过空行和冒号自然分段（例如：“漏洞名称：...”、“披露日期：...”、“漏洞描述：...”）；
4. 内容应自然组织，包含但不限于以下要素（如有）：
   - 漏洞名称与编号
   - 披露日期与信息来源
   - CVSS 评分（含完整向量）及风险等级（如 Critical）
   - 受影响产品及精确版本范围（如使用<,>和=）
   - 漏洞根本原因与技术原理（如 externalId 映射问题）
   - 触发条件（如配置项 enableSCIM=true 等）
   - 攻击者能力（是否远程？需权限？用户交互？）
   - 实际攻击影响（如账户劫持、权限提升、系统接管）
   - 利用状态：是否有公开 PoC？是否在野利用？利用复杂度？
   - 官方缓解措施（最好含具体配置示例，如 grafana.ini 修改）
   - 官方公告链接、CWE 编号、关联漏洞
   - 针对安全团队的 actionable 建议（如“立即禁用”、“监控日志”）
   - 参考链接（一个）
4. 忠实于原文，不得编造未提及的信息；
5. 若某项信息原文未提，可省略，无需写“未提及”；
6. 语言简洁专业，避免冗余解释或开场白。
""".format(cve_id=cve_id)),
            ("user", "{text}")
        ])

        chain = prompt | self.llm | StrOutputParser()
        try:
            summary = await chain.ainvoke({"text": text})
            return summary.strip()
        except Exception as e:
            error_msg = f"LLM 处理失败: {str(e)}"
            print(f"[!] {error_msg}", file=sys.stderr)
            return error_msg

    def save_summary(self, cve_id: str, summary: str):
        """
        Save summary to replace the original txt file.

        Args:
            cve_id: CVE ID to save for
            summary: Summary content to save
        """
        # 将精简后的内容直接替换原来的txt文件
        output_path = Path(f"{self.scraped_data_dir}/{cve_id}.txt")
        output_path.write_text(summary, encoding="utf-8")
        print(f"[+] 已将精简后的内容替换原始文件: {output_path}")
