# -*- coding: utf-8 -*-
# @Time    : 2020/12/20 17:54:58
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : filetypes.py
# @Software: Visual Studio Code


from math import e
# import magic

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
    'ole': 'ole'
}

OTHER_LIST = ['vba', 'exe', 'pdf']

MAGIC_TYPE_MAPPING = {
    'eml': 'eml',
    'html': 'html',
    'zip': 'zip',
    'doc': 'ole',
    'docx': 'zip',
    'xls': 'ole',
    'xlsx': 'zip',
    'ppt': 'ole',
    'pptx': 'zip',
}


# def get_magic_type(content):
#     try:
#         magic_type = magic.from_buffer(content)
#         return magic_type
#     except Exception as e:
#         return 'other'


def get_support_file_type(ext):
    return FILE_TYPE_MAPPING.get(ext, 'other')
