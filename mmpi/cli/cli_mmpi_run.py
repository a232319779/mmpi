# -*- coding: utf-8 -*-
# @Time     : 2023/01/18 15:22:25
# @Author   : ddvv
# @Site     : https://ddvvmmzz.github.io
# @File     : cli_mmpi_run.py
# @Software : Visual Studio Code
# @WeChat   : NextB


import json
import argparse
from mmpi.version import NEXTB_MMPI_VERSION
from mmpi.main import mmpi


def parse_cmd():
    """
    解析命令行参数
    """
    parser = argparse.ArgumentParser(
        prog="nextb-mmpi-run",
        description="使用nextb-mmpi-run工具扫描指定邮件，并输出扫描报告。版本号：{}".format(
            NEXTB_MMPI_VERSION
        ),
        epilog="使用方式：nextb-mmpi-run -f $eml_file",
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


def scans(email_file):
    mmpi_ins = mmpi()
    mmpi_ins.parse(email_file)
    report = mmpi_ins.get_report()
    print(json.dumps(report, indent=4, ensure_ascii=False))


def run():
    """
    CLI命令行入口
    """
    args = parse_cmd()
    if args.email_file:
        scans(args.email_file)
    else:
        print("邮件文件不能为空。请使用 -h 参数查看帮助。")
