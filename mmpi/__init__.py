# -*- coding: utf-8 -*-
# @Time    : 2020/12/23 01:59:33 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : __init__.py 
# @Software: Visual Studio Code


from mmpi import processing

signatures = []

# Don't include machinery here as its data structure is different from the
# other plugins - of which multiple are in use at any time.
plugins = {
    "processing": processing.plugins,
    "signatures": signatures,
}

from mmpi.main import mmpi