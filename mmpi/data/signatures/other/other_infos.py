# -*- coding: utf-8 -*-
# @Time    : 2020/12/20 16:39:47 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : rtf_infos.py 
# @Software: Visual Studio Code

from mmpi.common.filetypes import OTHER_LIST
from data_lib.mmpi.common.abstracts import Signature


class YaraDetected(Signature):
    authors = ["ddvv"]
    sig_type = 'other'
    name = "yara_detected"
    severity = 9
    description = "detected from yara rule"

    def on_complete(self):
        results = self.get_results()
        for result in results:
            if result.get('type', '') in OTHER_LIST:
                infos = result.get('value', {}).get('infos', [])
                if infos:
                    for info in infos:
                        name = info.get('name', '')
                        description = info.get('description', '')
                        severity = info.get('severity', 0)
                        yara_type = info.get('type', '')
                        self.mark(type=yara_type, tag=name, description=description, severity=severity)
                    return self.has_marks()
        return None
