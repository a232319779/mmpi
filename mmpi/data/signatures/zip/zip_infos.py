# -*- coding: utf-8 -*-
# @Time    : 2020/12/20 16:39:47 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : zip_infos.py 
# @Software: Visual Studio Code

import xml.etree.ElementTree as ET
from data_lib.mmpi.common.abstracts import Signature


class DLLHijacking(Signature):
    authors = ["ddvv"]
    sig_type = 'zip'
    name = "dll_hijacking"
    severity = 9
    description = "DLL Hijacking"

    def on_complete(self):
        results = self.get_results()
        for result in results:
            if result.get('type', '') == self.sig_type:
                infos = result.get('value', {}).get('infos', [])
                file_types = [info.get('type') for info in infos]
                if set(['exe', 'dll']).issubset(file_types):
                    self.mark(type="zip", tag=self.name)
                    return self.has_marks()
        return None


class ZipWithLnk(Signature):
    authors = ["ddvv"]
    sig_type = 'zip'
    name = "zip_with_lnk"
    severity = 6
    description = "Zip With Lnk File"

    def on_complete(self):
        results = self.get_results()
        for result in results:
            if result.get('type', '') == self.sig_type:
                infos = result.get('value', {}).get('infos', [])
                for info in infos:
                    file_type = info.get('type')
                    if 'lnk' == file_type:
                        self.mark(type="zip", tag=self.name, data=info.get('name'))
                        return self.has_marks()
        return None


class ZipWithPE(Signature):
    authors = ["ddvv"]
    sig_type = 'zip'
    name = "zip_with_pe"
    severity = 6
    description = "Zip With PE File"

    def on_complete(self):
        results = self.get_results()
        for result in results:
            if result.get('type', '') == self.sig_type:
                infos = result.get('value', {}).get('infos', [])
                for info in infos:
                    file_type = info.get('type')
                    if 'exe' == file_type:
                        self.mark(type="zip", tag=self.name, data=info.get('name'))
                        return self.has_marks()
        return None


class PEFakeDocument(Signature):
    authors = ["ddvv"]
    sig_type = 'zip'
    name = "pe_fake_document"
    severity = 9
    description = "PE File Fake Document"

    def on_complete(self):
        results = self.get_results()
        for result in results:
            if result.get('type', '') == self.sig_type:
                infos = result.get('value', {}).get('infos', [])
                for info in infos:
                    file_type = info.get('type', '')
                    file_name = info.get('name', '')
                    space_count = file_name.count('  ')
                    if 'exe' == file_type and space_count > 20:
                        self.mark(type="zip", tag=self.name, data=info.get('name'))
                        return self.has_marks()
        return None


class InvalidZipFile(Signature):
    authors = ["ddvv"]
    sig_type = 'zip'
    name = "invalid_zip_file"
    severity = 3
    description = "Invalid Zip File"

    def on_complete(self):
        results = self.get_results()
        for result in results:
            if result.get('type', '') == self.sig_type:
                infos = result.get('value', {}).get('infos', [])
                for info in infos:
                    file_type = info.get('type')
                    if file_type is None:
                        message = info.get('message')
                        self.mark(type="zip", tag=self.name, data=message)
                        return self.has_marks()
        return None


class OfficeTemplateInject(Signature):
    authors = ["ddvv"]
    sig_type = 'zip'
    name = "office_template_inject"
    severity = 9
    description = "Office Template Inject"

    def parse_xml(self, data):
        xml = ET.ElementTree(ET.fromstring(data))
        targets = list()
        for a in xml.iter():
            attrib = a.attrib
            targetmode = attrib.get('TargetMode', '')
            if targetmode == 'External':
                target = attrib.get('Target')
                targets.append(target)
        return targets


    def on_complete(self):
        results = self.get_results()
        for result in results:
            if result.get('type', '') == self.sig_type:
                datas = result.get('value', {}).get('datas', [])
                for data in datas:
                    file_type = data.get('file_type')
                    if file_type =='rels':
                        content = data.get('content')
                        if content:
                            targets = self.parse_xml(content)
                            for target in targets:
                                self.mark(type="zip", tag=self.name, data=target)
                            return self.has_marks()
        return None