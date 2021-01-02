# -*- coding: utf-8 -*-
# @Time    : 2020/12/23 01:57:47 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : exceptions.py 
# @Software: Visual Studio Code


class CriticalError(Exception):
    """critical error."""


class DependencyError(CriticalError):
    """Missing dependency error."""


class ProcessingError(CriticalError):
    """Error in processor module."""
