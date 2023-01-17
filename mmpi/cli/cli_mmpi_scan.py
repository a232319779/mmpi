# -*- coding: utf-8 -*-
# @Time     : 2023/01/17 15:15:49
# @Author   : ddvv
# @Site     : https://ddvvmmzz.github.io
# @File     : cli_mmpi_scan.py
# @Software : Visual Studio Code
# @WeChat   : NextB


import argparse
from colorama import Fore
from colorama import init
from mmpi.version import NEXTB_MMPI_VERSION
from mmpi.common.common import get_file_list
from mmpi.main import mmpi


def parse_cmd():
    """
    解析命令行参数
    """
    parser = argparse.ArgumentParser(
        prog="nextb-mmpi-scan",
        description="使用nextb-mmpi-scan工具扫描指定的邮件目录或者邮件文件。版本号：{}".format(
            NEXTB_MMPI_VERSION
        ),
        epilog="使用方式：nextb-mmpi-scan -d $eml_dir",
    )
    parser.add_argument(
        "-d",
        "--dir",
        help="指定扫描路径。路径参数优先级最高，指定 -d 参数后，会自动忽略 -f 参数。",
        type=str,
        dest="email_dir",
        action="store",
        default=None,
    )
    parser.add_argument(
        "-f",
        "--file",
        help="指定扫描文件.",
        type=str,
        dest="email_file",
        action="store",
        default=None,
    )

    args = parser.parse_args()

    return args


def scans(email_files):
    mmpi_ins = mmpi()
    init(autoreset=True)
    print(Fore.CYAN + "nextb-mmpi-scan扫描开始...")
    for ef in email_files:
        mmpi_ins.parse(ef)
        report = mmpi_ins.get_report()
        signatures = report.get("signatures", [])
        if signatures:
            names = [s.get("name") for s in signatures]
            names_str = "|".join(names)
            print("{} -- {}{}".format(ef, Fore.RED, names_str))
        else:
            print("{} -- {}安全".format(ef, Fore.GREEN))
    print(Fore.CYAN + "nextb-mmpi-scan扫描完成...")


def run():
    """
    CLI命令行入口
    """
    args = parse_cmd()
    if args.email_dir:
        email_files = get_file_list(args.email_dir)
        scans(email_files)
    elif args.email_file:
        scans([args.email_file])
    else:
        print("邮件路径或者邮件文件不能为空。请使用 -h 参数查看帮助。")
