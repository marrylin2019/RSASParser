import importlib
from ..utils import Cfg

config = Cfg()
version_module_name = config.rsas_version.replace('.', '_')
try:
    # 动态导入版本子模块
    module = importlib.import_module(f".{version_module_name}", package=__name__)
except ImportError as e:
    print(e)
    raise ImportError(
        f"不支持的绿盟漏扫版本：'{config.rsas_version}'。请确保 'Versions/{version_module_name}' 文件存在。"
    )
try:
    parse = getattr(module, 'parse')
    __all__ = ['Cfg', 'parse']
except AttributeError:
    raise AttributeError(f"版本模块 '{version_module_name}' 中未定义 'parse' 对象。请检查该模块。")

# # 清理命名空间，避免意外暴露局部变量
del version_module_name, module, config, importlib
