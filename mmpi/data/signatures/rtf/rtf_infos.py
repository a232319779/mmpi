# -*- coding: utf-8 -*-
# @Time    : 2020/12/20 16:39:47 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : rtf_infos.py 
# @Software: Visual Studio Code


from data_lib.mmpi.common.abstracts import Signature


class RTFSuspiciousDetected(Signature):
    authors = ["ddvv"]
    sig_type = 'rtf'
    name = "rtf_suspicious_detected"
    severity = 3
    description = "RTF Suspicious Detected"

    def on_complete(self):
        results = self.get_results()
        for result in results:
            if result.get('type', '') == self.sig_type:
                infos = result.get('value', {}).get('infos', [])
                for info in infos:
                    if info.get('is_ole', False):
                        self.mark(type="rtf", tag=self.name)
                        return self.has_marks()
        return None


class RTFExploitDetected(Signature):
    authors = ["ddvv"]
    sig_type = 'rtf'
    name = "rtf_exploit_detected"
    severity = 9
    description = "RTF Exploit Detected"

    def on_complete(self):
        results = self.get_results()
        for result in results:
            if result.get('type', '') == self.sig_type:
                infos = result.get('value', {}).get('infos', [])
                for info in infos:
                    if info.get('is_ole', False):
                        class_name = info.get('class_name', '')
                        if class_name == 'OLE2Link' or class_name.lower().startswith('equation'):
                            self.mark(type="rtf", tag=self.name)
                            return self.has_marks()
        return None
