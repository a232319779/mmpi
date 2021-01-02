# -*- coding: utf-8 -*-
# @Time    : 2020/12/23 01:57:20 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : __init__.py 
# @Software: Visual Studio Code


from ..compat import enumerate_signatures

plugins = enumerate_signatures(
    __file__, "eml", globals(), dict()
)
