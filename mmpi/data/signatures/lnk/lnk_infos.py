# -*- coding: utf-8 -*-
# @Time    : 2021/01/14 00:28:17 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : lnk_infos.py 
# @Software: Visual Studio Code


from data_lib.mmpi.common.abstracts import Signature


class LnkExecCMD(Signature):
    authors = ["ddvv"]
    sig_type = 'lnk'
    name = "lnk_exec_cmd"
    severity = 6
    description = "lnk exec cmd"

    def on_complete(self):
        results = self.get_results()
        for result in results:
            if result.get('type', '') == self.sig_type:
                infos = result.get('value', {}).get('infos', [])
                for info in infos:
                    relativePath = info.get('data', {}).get('relativePath', '')
                    if relativePath:
                        if relativePath.endswith('cmd.exe'):
                            self.mark(type="lnk", tag=self.name, relativePath=relativePath)
                            return self.has_marks()
        return None


class LnkDownloadFile(Signature):
    authors = ["ddvv"]
    sig_type = 'lnk'
    name = "lnk_download_file"
    severity = 9
    description = "lnk download file"

    def on_complete(self):
        results = self.get_results()
        for result in results:
            if result.get('type', '') == self.sig_type:
                infos = result.get('value', {}).get('infos', [])
                for info in infos:
                    commandLineArguments = info.get('data', {}).get('commandLineArguments', '')
                    if commandLineArguments:
                        if 'downloadfile' in commandLineArguments:
                            self.mark(type="lnk", tag=self.name, commandLineArguments=commandLineArguments)
                            return self.has_marks()
        return None