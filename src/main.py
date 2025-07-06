import sys
import shutil
import multiprocessing
from pathlib import Path

from modules import Cfg, extract_zip, parse, MainWindow


def execute(in_: Path, out_: Path):
    config = Cfg()
    # 清理临时目录
    if config.tmp_path.exists():
        shutil.rmtree(config.tmp_path)
    extract_zip(in_, config.tmp_path)
    hosts = [filename for filename in config.hosts.rglob(config.html_name_temp)]
    try:
        combined_df = parse(config, hosts)
    except Exception as e:
        print(f"解析过程中发生错误: {e}")
        shutil.rmtree(config.tmp_path) # 清理临时目录
        sys.exit(1)
    # 写入Excel
    output_path = Path(out_)
    output_path.parent.mkdir(parents=True, exist_ok=True)  # 确保输出目录存在
    combined_df.write_excel(output_path)
    # 删除.tmp
    shutil.rmtree(config.tmp_path)

if __name__ == '__main__':
    # 对Windows平台打包后的程序尤其重要
    multiprocessing.freeze_support()

    try:
        MainWindow(execute).show()
    except Exception as e:
        print(f"程序发生未处理的错误: {e}")
        # 在实际应用中，你可能希望记录更详细的traceback
        import traceback

        traceback.print_exc()
        sys.exit(1)
