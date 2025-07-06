import os
import sys
import toml
import zipfile
from pathlib import Path
from types import SimpleNamespace


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
        self.__cfg: dict = toml.load(_BASE/"resources/configs/base_config.toml")
        self.tmp_path = _BASE/self.__cfg['tmp_folder']
        self.index_html = self.tmp_path / self.__cfg['index_html']
        self.hosts = self.tmp_path / self.__cfg['htmls_folder']
        self.html_name_temp = self.__cfg['html_name_template']
        self.rsas_version = self.__cfg['rsas_version']
        self.exe_title = self.__cfg['exe_title']
        self.__icons_folder = _BASE / self.__cfg['icons_folder']
        self.ICONS = SimpleNamespace(**{key: self.__get_icon_path(key) for key in self.__cfg['icons']})

    def __get_icon_path(self, icon: str) -> Path:
        """
        获取图标的绝对路径
        :param icon: 图标名称
        :return: 图标的绝对路径
        """
        if icon not in self.__cfg['icons'].keys():
            raise ValueError(f"图标 '{icon}' 不存在")
        return self.__icons_folder / self.__cfg['icons'][icon]

# 解压整个ZIP包到指定目录
def extract_zip(zip_path: Path, output_dir: Path):
    os.makedirs(output_dir, exist_ok=True)  # 创建输出目录（若不存在）
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(output_dir)  # 解压所有文件
