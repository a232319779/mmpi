# -*- coding: utf-8 -*-
# @Time    : 2020/12/20 17:39:30 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : __init__.py 
# @Software: Visual Studio Code


from ..compat import enumerate_signatures

plugins = enumerate_signatures(
    __file__, "zip", globals(), dict()
)