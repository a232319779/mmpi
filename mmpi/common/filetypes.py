# -*- coding: utf-8 -*-
# @Time    : 2020/12/20 17:54:58
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : filetypes.py
# @Software: Visual Studio Code


FILE_TYPE_MAPPING = {
    'eml': 'eml',
    'html': 'html',
    'zip': 'zip',
    'doc': 'ole',
    'docx': 'zip',
    'xls': 'ole',
    'xlsx': 'zip',
    'ppt': 'ole',
    'pptx': 'zip',
    'rtf': 'rtf',
    'vba': 'vba',
    'exe': 'exe',
    'pdf': 'pdf',
    'ole': 'ole',
    'lnk': 'lnk',
}

OTHER_LIST = ['vba', 'exe', 'pdf', 'bat']

def get_support_file_type(ext):
    return FILE_TYPE_MAPPING.get(ext, 'other')
