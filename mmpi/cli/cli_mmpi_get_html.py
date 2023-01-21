# -*- coding: utf-8 -*-
# @Time     : 2023/01/21 11:12:24
# @Author   : ddvv
# @Site     : https://ddvvmmzz.github.io
# @File     : cli_mmpi_get_html.py
# @Software : Visual Studio Code
# @WeChat   : NextB


import os
import argparse
from tqdm import tqdm
from mmpi.version import NEXTB_MMPI_VERSION
from mmpi.common.common import get_file_list
from mmpi.main import mmpi


def parse_cmd():
    """
    解析命令行参数
    """
    parser = argparse.ArgumentParser(
        prog="nextb-mmpi-get-html",
        description="使用nextb-mmpi-get-html工具获取指定邮件的正文，并输出正文内容。版本号：{}".format(
            NEXTB_MMPI_VERSION
        ),
        epilog="使用方式：nextb-mmpi-get-html -g $eml_file",
    )

    parser.add_argument(
        "-g",
        "--get-html",
        help="指定扫描文件或者目录.",
        type=str,
        dest="get_html",
        action="store",
        default=None,
    )

    args = parser.parse_args()

    return args


def scans(email_files):
    mmpi_ins = mmpi()
    results = dict()
    for ef in tqdm(email_files, unit="eml", desc="{}nextb-mmpi-get-html解析中".format("")):
        mmpi_ins.parse(ef)
        report = mmpi_ins.get_report()
        results[ef] = report.get("body", [])
    for eml, bodys in results.items():
        print("{}{}{}".format(20 * "-", eml, 20 * "-"))
        for body in bodys:
            print(body.get("content"))


def run():
    """
    CLI命令行入口
    """
    args = parse_cmd()
    if os.path.isdir(args.get_html):
        email_files = get_file_list(args.get_html)
        scans(email_files)
    else:
        scans([args.get_html])
