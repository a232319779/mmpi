# -*- coding: utf-8 -*-
# @Time     : 2023/01/17 15:15:49
# @Author   : ddvv
# @Site     : https://ddvvmmzz.github.io
# @File     : cli_mmpi_scan.py
# @Software : Visual Studio Code
# @WeChat   : NextB


import os
import argparse
from colorama import Fore, Style
from prettytable import PrettyTable
from tqdm import tqdm
from mmpi.version import NEXTB_MMPI_VERSION
from mmpi.common.common import get_file_list
from mmpi.main import mmpi


def parse_cmd():
    """
    解析命令行参数
    """
    parser = argparse.ArgumentParser(
        prog="nextb-mmpi-scan",
        description="使用nextb-mmpi-scan工具扫描指定的email目录或者email文件。版本号：{}".format(
            NEXTB_MMPI_VERSION
        ),
        epilog="使用方式：nextb-mmpi-scan -s $eml_dir",
    )
    parser.add_argument(
        "-s",
        "--scan",
        help="扫描指定的email路径或者email文件。",
        type=str,
        dest="emails",
        action="store",
        default=None,
    )

    args = parser.parse_args()

    return args


def scans(email_files):
    mmpi_ins = mmpi()
    results = list()
    for ef in tqdm(
        email_files, unit="eml", desc="{}nextb-mmpi-scan扫描中".format(Fore.CYAN)
    ):
        mmpi_ins.parse(ef)
        report = mmpi_ins.get_report()
        signatures = report.get("signatures", [])
        if signatures:
            names = [s.get("name") for s in signatures]
            names_str = "|".join(names)
            tags = "{}{}{}".format(Fore.RED, names_str, Style.RESET_ALL)
        else:
            tags = "{}未检出{}".format(Fore.GREEN, Style.RESET_ALL)
        results.append([ef, tags])
    x = PrettyTable()
    x.field_names = ["邮件名称", "NextB-mmpi命中标签"]
    x.add_rows(results)
    print(x)


def run():
    """
    CLI命令行入口
    """
    args = parse_cmd()
    if os.path.isdir(args.emails):
        email_files = get_file_list(args.emails)
        scans(email_files)
    else:
        scans([args.emails])
