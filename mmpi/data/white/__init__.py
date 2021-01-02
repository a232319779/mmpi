# -*- coding: utf-8 -*-
# @Time    : 2020/12/24 23:34:22 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : __init__.py 
# @Software: Visual Studio Code


import os
from urllib.parse import urlparse


def read_domains(filename):
    with open(filename, 'r') as target:
        data = target.readlines()
        return [d.strip() for d in data]

basedir = os.path.dirname(__file__)
filter_file = os.path.join(basedir, 'filter_domains.txt')
short_file = os.path.join(basedir, 'short_domains.txt')

FILTER_DOMAINS = read_domains(filter_file)
SHORT_DOMAINS = read_domains(short_file)


def check_fitler_domain(http_url):
    """
    domain过滤检测，仅检测二级或者三级域名
    返回值：
    True：过滤
    False：不过滤单
    """
    uri = urlparse(http_url)
    domain_name = f"{uri.netloc}"
    domain_list = domain_name.split(':')[0].split('.')
    if len(domain_list) < 2:
        return True
    elif len(domain_list) > 2 and domain_list[-2] in ['com', 'org', 'net', 'int', 'edu', 'gov', 'co']:
        # 取三级域名
        new_domain_name = '.'.join(domain_list[-3:])
    else:
        # 取二级域名
        new_domain_name = '.'.join(domain_list[-2:])
    if new_domain_name in FILTER_DOMAINS:
            return True
    return False