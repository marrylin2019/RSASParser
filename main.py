import os
import sys
import toml
import json
import shutil
import zipfile 
import argparse
import polars as pl
from enum import Enum
import multiprocessing
from lxml import etree
from pathlib import Path
from functools import partial
from concurrent.futures import ProcessPoolExecutor


class TEMPLATE_TYPE(Enum):
    WEB = 'Web全部应用漏洞'
    AUTO = '自动匹配扫描'
    ALL = '全部漏洞扫描'


level_map = {
    'low': '低',
    'middle': '中',
    'high': '高'
}
boolean_map = {
    False: '否',
    True: '是'
}


class Cfg:
    def __init__(self, config_path: Path):
        self.__cfg: dict = toml.load(config_path) 
        self.tmp_path = Path(self.__cfg['tmp_folder'])
        self.index_html = self.tmp_path/self.__cfg['index_html']

    @property
    def hosts(self) -> Path:
        return Path(self.__cfg['tmp_folder']) / self.__cfg['htmls_folder']
    
    @property
    def html_name_temp(self) -> str:
        return self.__cfg['html_name_template']


# TODO: 将AutoTemparser和WebTemparser抽象出父类，同时temp_type_detector也需要修改
# TODO: Temparser需要更健壮
class AllTemparser:
    SCHEMA = {
        'IP地址': pl.Utf8,
        '端口': pl.Utf8,
        '服务': pl.Utf8,
        '协议': pl.Utf8,
        '漏洞名称': pl.Utf8,
        '漏洞级别': pl.Utf8,
        '详细描述': pl.Utf8,
        '解决方案': pl.Utf8,
        '威胁分值': pl.Utf8,
        '危险插件': pl.Utf8,
        '发现日期': pl.Utf8,
        'CVE编号': pl.Utf8,
        '扫描起始时间': pl.Utf8,
        '扫描结束时间': pl.Utf8,
        '漏洞ID': pl.Utf8,
    }

    def __init__(self, html: Path):
        elem = etree.HTML(html.read_text(encoding="utf-8"), etree.HTMLParser(huge_tree=True))
        self.rows = []
        self.__data = json.loads(elem.xpath("//script[1]/text()")[0].replace("window.data = ", '').replace(';', ''))
        self.__data = self.__data['categories']
        self.__main_info = self.__data[1]['children'][1]['data']
        self.ip_addr = self.__data[0]['data']['target']
        self.scan_start_time = self.__data[0]['data']['timeStart']
        self.scan_end_time = self.__data[0]['data']['timeEnd']
        self.__parse()

    def __parse(self):
        for outer_dict in self.__main_info['vul_items']:
            port = outer_dict['port']
            service = outer_dict['service']
            protocol = outer_dict['protocol']

            for inner_dict in outer_dict['vuls']:
                vul_msg = inner_dict['vul_msg']
                self.rows.append({
                    'IP地址': self.ip_addr,
                    '端口': port,
                    '服务': service,
                    '协议': protocol,
                    '漏洞名称': vul_msg['i18n_name'],
                    '漏洞级别': level_map[inner_dict['vul_level']],
                    '详细描述': ''.join([i if i else '\r\n' for i in vul_msg['i18n_description']]),
                    '解决方案': ''.join([i if i else '\r\n' for i in vul_msg['i18n_solution']]),
                    '威胁分值': vul_msg['severity_points'],
                    '危险插件': boolean_map[vul_msg['is_dangerous']], 
                    '发现日期': vul_msg['date_found'],
                    'CVE编号': vul_msg['cve_id'],
                    '扫描起始时间': self.scan_start_time,
                    '扫描结束时间': self.scan_end_time,
                    '漏洞ID': inner_dict['vul_id'],
                })

    # def to_df(self) -> pl.DataFrame:
    #     """将原始数据转换为Polars DataFrame"""
    #     return pl.DataFrame(self.rows, schema=self.get_schema())


class WebTemparser:
    SCHEMA = {
            'IP地址': pl.Utf8,
            'URL': pl.Utf8,
            '请求方式': pl.Utf8,
            '问题参数': pl.Utf8,
            '参考（验证）': pl.Utf8,
            '漏洞名称': pl.Utf8,
            '威胁分值': pl.Utf8,
            '漏洞级别': pl.Utf8,
            'CVSS评分': pl.Utf8,
            '详细描述': pl.Utf8,
            '解决办法': pl.Utf8,
            '危险插件': pl.Utf8,
            '原始请求': pl.Utf8,
            '原始响应': pl.Utf8,
            '扫描起始时间': pl.Utf8,
            '扫描结束时间': pl.Utf8,
        }

    def __init__(self, html: Path):
        elem = etree.HTML(html.read_text(encoding="utf-8"), etree.HTMLParser(huge_tree=True))
        # print(html.read_text(encoding="utf-8"))
        self.rows = []
        self.__data = json.loads(elem.xpath("//script[1]/text()")[0].replace("window.data = ", '').replace(';', ''))
        self.__data = self.__data['categories']
        self.__main_info = self.__data[2]['children'][1]['data']['risk_distribution']['web_scan_vuls_list']
        self.ip_addr = self.__data[0]['data']['target']
        # self.url = self.__data[0]['data']['target']
        self.scan_start_time = self.__data[0]['data']['timeStart']
        self.scan_end_time = self.__data[0]['data']['timeEnd']
        self.__parse()

    def __parse(self):
        for outer_dict in self.__main_info:
            vul_name = outer_dict['i18n_name'] # 漏洞名称
            severity_points = outer_dict['severity_points'] # 威胁分值
            risk_level = level_map[outer_dict['risk_level']] # 漏洞级别
            vul_info = outer_dict['web_vuln_obj']
            cvss = vul_info['cvss'] # CVSS评分
            description = vul_info['i18n_description'] # 详细描述
            solution = vul_info['i18n_solution'] # 解决办法
            is_dangerous = boolean_map[vul_info['is_dangerous']] # 危险插件

            for inner_dict in outer_dict['pages']:
                raw_req_info = inner_dict['raw_data'][0]['request']
                raw_res_info = inner_dict['raw_data'][0]['response']
                raw_request = (
                        f'{raw_req_info["url"]}\n' +
                        ''.join([f"{item[0]}: {item[1]}\n" for item in raw_req_info["headers"]])
                )
                raw_response = (
                        f'{raw_res_info["status"]}\n' +
                        ''.join([f"{item[0]}: {item[1]}\n" for item in raw_res_info["headers"]]) +
                        ''.join([f"{item}\n" for item in raw_res_info['contents']])
                )
                self.rows.append({
                    'IP地址': self.ip_addr,
                    'URL': inner_dict['url'],
                    '请求方式': inner_dict.get('method', ''),
                    '问题参数': inner_dict.get('param', ''),
                    '参考（验证）': inner_dict.get('verification', ''),
                    '漏洞名称': vul_name,
                    '威胁分值': severity_points,
                    '漏洞级别': risk_level,
                    'CVSS评分': cvss,
                    '详细描述': description,
                    '解决办法': solution,
                    '危险插件': is_dangerous,
                    '原始请求': raw_request,
                    '原始响应': raw_response,
                    '扫描起始时间': self.scan_start_time,
                    '扫描结束时间': self.scan_end_time,
                })

    # def to_df(self) -> pl.DataFrame:
    #     """将原始数据转换为Polars DataFrame"""
    #     return pl.DataFrame(self.rows, schema=self.get_schema())


class PARSER_TYPE(Enum):
    WEB = WebTemparser
    ALL = AllTemparser
    AUTO = AllTemparser


def temp_type_detector(cfg: Cfg) -> TEMPLATE_TYPE:
    elem = etree.HTML(cfg.index_html.read_text(encoding="utf-8"))
    data = json.loads(elem.xpath("//script[1]//text()")[0].replace("window.data = ", '').replace(';', ''))
    vulnTemplate = data['categories'][0]['children'][0]['data']['vulnTemplate']
    try:
        return TEMPLATE_TYPE(vulnTemplate)
    except ValueError as e:
        print("Unimplemented template type!")
        exit(-1)

 
# 解压整个ZIP包到指定目录 
def extract_zip(zip_path: Path, output_dir: Path): 
    os.makedirs(output_dir, exist_ok=True)  # 创建输出目录（若不存在）
    with zipfile.ZipFile(zip_path, 'r') as zf: 
        zf.extractall(output_dir)   # 解压所有文件 


def parse_host(host, temp_type: TEMPLATE_TYPE) -> list[dict]:
    return PARSER_TYPE[temp_type.name].value(host).rows


def create_arg_parser():
    parser = argparse.ArgumentParser(
        description="绿盟V6.0R04F04SP06漏扫报告解析",
        epilog="示例: main.exe -i test.zip -o output.xlsx"
    )
    parser.add_argument('--input', '-i', type=str, required=True, help="待解析压缩包路径")
    parser.add_argument('--output', '-o', type=str, required=True, help="输出文件路径")
    return parser

def get_res_path() -> Path:
    base_path = getattr(sys, '_MEIPASS', Path(__file__).parent)
    return Path(base_path)

def run_main(args):
    config = Cfg(get_res_path() / "config/config.toml")
    extract_zip(Path(args.input), config.tmp_path)
    hosts = [filename for filename in config.hosts.rglob(config.html_name_temp)]
    temp_type = temp_type_detector(config)
    with ProcessPoolExecutor() as pool:
        parse_with_type = partial(parse_host, temp_type=temp_type)
        # 使用map并行处理所有host
        dfs = pool.map(parse_with_type, hosts)
    # 合并所有DataFrame
    # combined_df = pl.concat(dfs)
    combined_df = pl.DataFrame(
        [row for sublist in dfs for row in sublist],
        schema=PARSER_TYPE[temp_type_detector(config).name].value.SCHEMA
    )
    # 直接写入Excel，无需通过Parquet中转
    # 注意: 这需要你的环境中安装了 `xlsxwriter` 或 `openpyxl`
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True) # 确保输出目录存在
    combined_df.write_excel(output_path)
    # 删除.tmp
    shutil.rmtree(config.tmp_path)


if __name__ == '__main__':
    # 对Windows平台打包后的程序尤其重要
    multiprocessing.freeze_support()

    arg_parser = create_arg_parser()
    argus = arg_parser.parse_args()

    try:
        run_main(argus)
    except Exception as e:
        print(f"程序发生未处理的错误: {e}")
        # 在实际应用中，你可能希望记录更详细的traceback
        import traceback

        traceback.print_exc()
        sys.exit(1)
