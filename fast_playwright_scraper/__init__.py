"""
CVE OCR解耦模块
"""

from .browser_screenshot import BrowserScreenshot
from .ocr_processor import OCRProcessor
from .main_ocr import CVEOCREngine

__version__ = "0.1.0"
__all__ = [
    "BrowserScreenshot",
    "OCRProcessor",
    "CVEOCREngine"
]