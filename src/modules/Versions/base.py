import polars as pl
from lxml import etree
from pathlib import Path
from typing import List, Dict, Any
from abc import ABC, abstractmethod


class BaseTemparser(ABC):
    """基础模板解析器类"""
    def __init__(self, html: Path):
        """
        初始化模板解析器
        :param html: 待解析的HTML文件路径
        :param output_keys: 输出的键列表，输出表的字段顺序与此列表一致
        """
        self.elem = etree.HTML(html.read_text(encoding="utf-8"), etree.HTMLParser(huge_tree=True))
        # 要写入xlsx的行
        self.rows: List[Dict[str, Any]] = []
        self._parse()

    @classmethod
    def schema(cls, output_keys: List[str]) -> Dict[str, Any]:
        return {key: pl.Utf8 for key in output_keys}

    @abstractmethod
    def _parse(self):
        """解析HTML内容"""
        pass
