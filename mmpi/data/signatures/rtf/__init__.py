# -*- coding: utf-8 -*-
# @Time    : 2020/12/31 16:05:02 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : __init__.py 
# @Software: Visual Studio Code


from ..compat import enumerate_signatures

plugins = enumerate_signatures(
    __file__, "rtf", globals(), dict()
)