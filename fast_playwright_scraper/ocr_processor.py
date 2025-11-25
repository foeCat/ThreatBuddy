import io
import re
from PIL import Image, ImageFilter
import pytesseract


class OCRProcessor:
    """
    OCR图像处理器
    功能：图像预处理和OCR识别
    """

    def __init__(self, lang='eng'):
        self.lang = lang

    def preprocess_image(self, image_bytes):
        """
        图像预处理，提高OCR准确性
        :param image_bytes: 图像字节数据
        :return: 预处理后的PIL图像
        """
        img = Image.open(io.BytesIO(image_bytes))

        # 1. 转换为灰度
        img = img.convert('L')

        # 2. 使用自适应阈值处理
        img = img.point(lambda x: 255 if x > 150 else 0, mode='1')

        # 3. 去除噪声
        img = img.filter(ImageFilter.MedianFilter(size=1))

        # 4. 边缘增强
        img = img.filter(ImageFilter.SHARPEN)

        return img

    def ocr_image(self, image_bytes, cve_id=None):
        """
        对图像进行OCR识别
        :param image_bytes: 图像字节数据
        :param cve_id: 可选的CVE ID，用于验证结果是否相关
        :return: 识别的文本，如果指定了cve_id但未找到则返回None
        """
        preprocessed_img = self.preprocess_image(image_bytes)

        # 使用Tesseract的引擎模式和语言设置
        custom_config = r'--oem 3 --psm 6'
        text = pytesseract.image_to_string(preprocessed_img, lang=self.lang, config=custom_config).strip()

        if cve_id and text:
            pattern = r"\b" + re.escape(cve_id) + r"\b"
            return text if re.search(pattern, text, re.IGNORECASE) else None

        return text

    def ocr_image_file(self, image_path, cve_id=None):
        """
        从文件中读取图像并进行OCR识别
        :param image_path: 图像文件路径
        :param cve_id: 可选的CVE ID，用于验证结果是否相关
        :return: 识别的文本，如果指定了cve_id但未找到则返回None
        """
        with open(image_path, 'rb') as f:
            img_bytes = f.read()
        return self.ocr_image(img_bytes, cve_id)


if __name__ == "__main__":
    # 测试OCR处理器模块
    processor = OCRProcessor()

    # 测试1：查看帮助信息
    print("OCR Processor模块 - 可以独立运行")
    print("使用方法：")
    print("1. 将本模块导入其他脚本")
    print("2. 或者直接运行测试：python ocr_processor.py <image_path> [cve_id]")

    import sys
    if len(sys.argv) > 1:
        image_path = sys.argv[1]
        cve_id = sys.argv[2] if len(sys.argv) > 2 else None

        if cve_id:
            print(f"\n正在处理图像: {image_path}，验证CVE ID: {cve_id}")
        else:
            print(f"\n正在处理图像: {image_path}")

        result = processor.ocr_image_file(image_path, cve_id)
        if result:
            print("\nOCR结果：")
            print(result)
        else:
            if cve_id:
                print(f"\nOCR识别失败或未找到CVE ID: {cve_id}")
            else:
                print("\nOCR识别失败")