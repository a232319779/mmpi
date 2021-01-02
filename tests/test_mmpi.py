# -*- coding: utf-8 -*-
# @Time    : 2020/12/23 00:56:01
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : test_mmpi.py
# @Software: Visual Studio Code


import unittest
import os
import json
from mmpi import mmpi


class Testmmpi(unittest.TestCase):

    def test_process(self):
        mmpi_ins = mmpi()
        test_path = os.path.dirname(__file__)
        test_samples = os.path.join(test_path, "samples")
        files = os.listdir(test_samples)
        for f in files:
            test_sample = os.path.join(test_samples, f)
            print(test_sample)
            mmpi_ins.parse(test_sample)
            report = mmpi_ins.get_report()
            print(json.dumps(report, indent=4))
