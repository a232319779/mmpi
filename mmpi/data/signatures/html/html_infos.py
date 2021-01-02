# -*- coding: utf-8 -*-
# @Time    : 2020/12/20 16:25:45
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : html_infos.py
# @Software: Visual Studio Code


from data_lib.mmpi.common.abstracts import Signature
from mmpi.data.white import check_fitler_domain


class ProbeDetection(Signature):
    authors = ["ddvv"]
    sig_type = 'html'
    name = "probe_detection"
    severity = 6
    description = "Mail Probe Detection"

    def on_complete(self):
        results = self.get_results()
        for result in results:
            if result.get('type', '') == self.sig_type:
                infos = result.get('value', {}).get('infos', [])
                complex_number = len(infos)
                if complex_number < 5:
                    for info in infos:
                        if info.get('type', '') == 'img':
                            data = info.get('data', {})
                            src = data.get('src', '')
                            # suffix = src.split('.')[-1]
                            # if suffix not in ['gif', 'png', 'jpeg', 'jpg', 'pic'] and not check_fitler_domain(src):
                            if not check_fitler_domain(src):
                                width = data.get('width', 9999)
                                height = data.get('height', 9999)
                                if width + height <= 2:
                                        self.mark(type="html", data=data.get('src'), tag=self.name)
                    return self.has_marks()
        return None

class PhishingDetection(Signature):
    authors = ["ddvv"]
    sig_type = 'html'
    name = "phishing_detection"
    severity = 6
    description = "Mail Phishing Detection"

    def on_complete(self):
        results = self.get_results()
        marks = list()
        for result in results:
            if result.get('type', '') == self.sig_type:
                infos = result.get('value', {}).get('infos', [])
                for info in infos:
                    if info.get('type', '') == 'hyperlink':
                        data = info.get('data', {})
                        src = data.get('src')
                        if not check_fitler_domain(src):
                            word = data.get('word')
                            if word not in src:
                                last_word = src.replace('/', '')[-4:].lower()
                                url_param = src.split('&')
                                url_path = src.split('/')
                                domains = word.replace('www.', '')
                                complex_number = len(infos)
                                if (last_word != word[-4:].lower() or complex_number < 5) and domains not in src and len(url_param) < 4 and (last_word == '.php' or len(url_path) < 12):
                                    # self.mark(type="html", data=data.get('src'), tag=self.name)
                                    marks.append({"type": "html", "data": data.get("src"), "tag": self.name})
        if marks and len(marks) < 5:
            for mark in marks:
                self.mark(**mark)
            return self.has_marks()
        else:
            return None

class SPAMDetection(Signature):
    authors = ["ddvv"]
    sig_type = 'html'
    name = "spam_detection"
    severity = 3
    description = "SPAM Detection"

    def on_complete(self):
        results = self.get_results()
        for result in results:
            if result.get('type', '') == self.sig_type:
                infos = result.get('value', {}).get('infos', [])
                complex_number = len(infos)
                if complex_number > 9:
                    self.mark(type="html", tag=self.name)
                    return self.has_marks()
        return None
