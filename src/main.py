import sys
import shutil
import argparse
import multiprocessing
from pathlib import Path

from modules import Cfg, extract_zip, parse


def create_arg_parser():
    arg_parser = argparse.ArgumentParser(
        description="绿盟V6.0R04F04SP06漏扫报告解析",
        epilog="示例: main.exe -i test.zip -o output.xlsx"
    )
    arg_parser.add_argument('--input', '-i', type=str, required=True, help="待解析压缩包路径")
    arg_parser.add_argument('--output', '-o', type=str, required=True, help="输出文件路径")
    return arg_parser.parse_args()


def run_main(args):
    config = Cfg()
    # 清理临时目录
    if config.tmp_path.exists():
        shutil.rmtree(config.tmp_path)
    extract_zip(Path(args.input), config.tmp_path)
    hosts = [filename for filename in config.hosts.rglob(config.html_name_temp)]
    try:
        combined_df = parse(config, hosts)
    except Exception as e:
        print(f"解析过程中发生错误: {e}")
        shutil.rmtree(config.tmp_path) # 清理临时目录
        sys.exit(1)
    # 写入Excel
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)  # 确保输出目录存在
    combined_df.write_excel(output_path)
    # 删除.tmp
    shutil.rmtree(config.tmp_path)
    print(f"解析完成，结果已保存到: {output_path}")


if __name__ == '__main__':
    # 对Windows平台打包后的程序尤其重要
    multiprocessing.freeze_support()
    argus = create_arg_parser()

    try:
        run_main(argus)
    except Exception as e:
        print(f"程序发生未处理的错误: {e}")
        # 在实际应用中，你可能希望记录更详细的traceback
        import traceback

        traceback.print_exc()
        sys.exit(1)
