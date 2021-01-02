# -*- coding: utf-8 -*-
# @Time    : 2020/12/23 01:59:09 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : __init__.py 
# @Software: Visual Studio Code


from mmpi.core.plugins import enumerate_plugins
from mmpi.common.abstracts import Processing

plugins = enumerate_plugins(
    __file__, "mmpi.processing", globals(), Processing
)
