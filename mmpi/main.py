# -*- coding: utf-8 -*-
# @Time    : 2020/12/18 22:02:31 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : main.py 
# @Software: Visual Studio Code


import json
import sys
from mmpi.core.plugins import RunProcessing, RunSignatures
from mmpi.common.filetypes import get_support_file_type
from mmpi.core.startup import init_modules
from mmpi.misc import load_signatures


class mmpi(object):

    def __init__(self):
        load_signatures()
        init_modules()
        self.results = list()
        self.reports = dict()

    def get_results(self):
        return self.results

    def process(self, data):
        file_type = get_support_file_type(data.get('file_type'))
        results = RunProcessing(data).run()
        if results:
            self.results.append(results)
            report = results.get('value').get('report', {})
            if report:
                self.reports.update(report)
            if file_type != 'other':
                datas = results.get('value', {}).get('datas', [])
                for data in datas:
                    self.process(data)

    def signatures(self, data):
        RunSignatures(data).run()

    def parse(self, filename):
        self.results = list()
        self.reports = dict()
        with open(filename, 'rb') as f:
            data = {'content': f.read(), 'file_type': 'eml'}
        if data.get('content', b''):
            self.process(data)
            self.signatures(self.results)
            self.reports['signatures'] = self.get_signatures()

    def get_report(self):
        return self.reports

    def get_signatures(self):
        signatures = list()
        for result in self.results:
            file_type = result.get('type')
            if file_type == 'signatures':
                infos = result.get('value', {}).get('infos')
                for info in infos:
                    marks = info.get('marks', [])
                    marks = [dict(t) for t in set([tuple(mark.items()) for mark in marks])]
                    info['marks'] = marks
                    signatures.append(info)

        return signatures


def main():
    mmpi_ins = mmpi()
    mmpi_ins.parse(sys.argv[1])
    report = mmpi_ins.get_report()
    print(json.dumps(report, indent=4))
