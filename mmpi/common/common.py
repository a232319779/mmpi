# -*- coding: utf-8 -*-
# @Time     : 2023/01/17 15:24:17
# @Author   : ddvv
# @Site     : https://ddvvmmzz.github.io
# @File     : common.py
# @Software : Visual Studio Code
# @WeChat   : NextB

import os

def get_file_list(file_dir):
    """
    遍历指定目录，获取文件路径
    """
    file_paths = list()
    for root, _, files in os.walk(file_dir):
        for file_name in files:
            file_paths.append(os.path.join(root, file_name))

    return file_paths
