import json
import itertools
import polars as pl
from lxml import etree
from pathlib import Path
from typing import Optional, List, Type
from concurrent.futures import ProcessPoolExecutor

from ..utils import Cfg
from .base import BaseTemparser


_LEVEL_MAP = {
    'low': '低',
    'middle': '中',
    'high': '高'
}

_BOOL_MAP = {
    False: '否',
    True: '是'
}


# TODO: Temparser需要更健壮
class _AllTemparser(BaseTemparser):
    @classmethod
    def SCHEMA(cls, output_keys: Optional[List[str]] = None):
        output_keys = output_keys if output_keys else [
            'IP地址', '端口', '服务', '协议', '漏洞名称', '漏洞级别', '详细描述', '解决方案',
            '威胁分值', '危险插件', '发现日期', 'CVE编号', '扫描起始时间', '扫描结束时间', '漏洞ID'
        ]
        return super().schema(output_keys)

    def _parse(self):
        data = json.loads(
            self.elem.xpath("//script[1]/text()")[0].replace("window.data = ", '').replace(';', '')
        )['categories']
        main_info = data[1]['children'][1]['data']
        ip_addr = data[0]['data']['target']
        scan_start_time = data[0]['data']['timeStart']
        scan_end_time = data[0]['data']['timeEnd']
        for outer_dict in main_info['vul_items']:
            for inner_dict in outer_dict['vuls']:
                vul_msg = inner_dict['vul_msg']
                self.rows.append({
                    'IP地址': ip_addr,
                    '端口': outer_dict['port'],
                    '服务': outer_dict['service'],
                    '协议': outer_dict['protocol'],
                    '漏洞名称': vul_msg['i18n_name'],
                    '漏洞级别': _LEVEL_MAP[inner_dict['vul_level']],
                    '详细描述': ''.join([i if i else '\r\n' for i in vul_msg['i18n_description']]),
                    '解决方案': ''.join([i if i else '\r\n' for i in vul_msg['i18n_solution']]),
                    '威胁分值': vul_msg['severity_points'],
                    '危险插件': _BOOL_MAP[vul_msg['is_dangerous']],
                    '发现日期': vul_msg['date_found'],
                    'CVE编号': vul_msg['cve_id'],
                    '扫描起始时间': scan_start_time,
                    '扫描结束时间': scan_end_time,
                    '漏洞ID': inner_dict['vul_id'],
                })


class _WebTemparser(BaseTemparser):
    @classmethod
    def SCHEMA(cls, output_keys: Optional[List[str]] = None):
        output_keys = output_keys if output_keys else [
            'IP地址', 'URL', '请求方式', '问题参数', '参考（验证）', '漏洞名称', '威胁分值',
            '漏洞级别', 'CVSS评分', '详细描述', '解决办法', '危险插件', '原始请求', '原始响应',
            '扫描起始时间', '扫描结束时间'
        ]
        return super().schema(output_keys)

    def _parse(self):
        data = json.loads(
            self.elem.xpath("//script[1]/text()")[0].replace("window.data = ", '').replace(';', '')
        )['categories']
        main_info = data[2]['children'][1]['data']['risk_distribution']['web_scan_vuls_list']
        ip_addr = data[0]['data']['target']
        # self.url = data[0]['data']['target']
        scan_start_time = data[0]['data']['timeStart']
        scan_end_time = data[0]['data']['timeEnd']
        for outer_dict in main_info:
            vul_name = outer_dict['i18n_name']  # 漏洞名称
            severity_points = outer_dict['severity_points']  # 威胁分值
            risk_level = _LEVEL_MAP[outer_dict['risk_level']]  # 漏洞级别
            vul_info = outer_dict['web_vuln_obj']
            cvss = vul_info['cvss']  # CVSS评分
            description = vul_info['i18n_description']  # 详细描述
            solution = vul_info['i18n_solution']  # 解决办法
            is_dangerous = _BOOL_MAP[vul_info['is_dangerous']]  # 危险插件

            for inner_dict in outer_dict['pages']:
                if len(inner_dict['raw_data']) == 0:
                    raw_request = ''
                    raw_response = ''
                else:
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
                    'IP地址': ip_addr,
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
                    '扫描起始时间': scan_start_time,
                    '扫描结束时间': scan_end_time,
                })


def _temparser_chooser(cfg: Cfg) -> Type[_WebTemparser]|Type[_AllTemparser]:
    elem = etree.HTML(cfg.index_html.read_text(encoding="utf-8"))
    data = json.loads(elem.xpath("//script[1]//text()")[0].replace("window.data = ", '').replace(';', ''))
    titles = [item['title'] for item in data['categories']]
    vulnTemplate = data['categories'][0]['children'][0]['data']['vulnTemplate']

    if '站点列表' in titles and '漏洞列表' in titles and not ('主机信息' in titles and '漏洞信息' in titles):
        return _WebTemparser
    elif '主机信息' in titles and '漏洞信息' in titles and not ('站点列表' in titles and '漏洞列表' in titles):
        return _AllTemparser
    else:
        raise ValueError(f"Unimplemented template type {vulnTemplate}!")

def parser_map(host: Path, temparser: Type[BaseTemparser]) -> List[dict]:
    return temparser(host).rows


def parse(config: Cfg, hosts: List[str]) -> pl.DataFrame:
    temparser = _temparser_chooser(config)

    with ProcessPoolExecutor() as pool:
        dfs = pool.map(parser_map, hosts, itertools.repeat(temparser, len(hosts)))
    # 合并所有DataFrame
    return pl.DataFrame(
        [row for sublist in dfs for row in sublist],
        schema=temparser.SCHEMA()
    )
