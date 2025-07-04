import os
import sys
import toml
import zipfile

from pathlib import Path


# 获取资源的绝对路径，兼容开发环境和 PyInstaller 打包环境
# 打包后Path(sys._MEIPASS)
# 开发时Path(__file__).parent.parent
_BASE = Path(sys._MEIPASS) if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS') \
            else Path(__file__).parent.parent.parent.absolute()

class Cfg:
    def __new__(cls, *args, **kwargs):
        """单例模式"""
        if not hasattr(cls, '_instance'):
            cls._instance = super(Cfg, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        self.__cfg: dict = toml.load(_BASE/"config/config.toml")
        self.tmp_path = _BASE/self.__cfg['tmp_folder']
        self.index_html = self.tmp_path / self.__cfg['index_html']

    @property
    def hosts(self) -> Path:
        return self.tmp_path / self.__cfg['htmls_folder']

    @property
    def html_name_temp(self) -> str:
        return self.__cfg['html_name_template']

    @property
    def rsas_version(self) -> str:
        return self.__cfg['rsas_version']


# 解压整个ZIP包到指定目录
def extract_zip(zip_path: Path, output_dir: Path):
    os.makedirs(output_dir, exist_ok=True)  # 创建输出目录（若不存在）
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(output_dir)  # 解压所有文件
