# -*- coding: utf-8 -*-
# @Time    : 2021/01/14 00:05:49 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : __init__.py 
# @Software: Visual Studio Code


from ..compat import enumerate_signatures

plugins = enumerate_signatures(
    __file__, "lnk", globals(), dict()
)