# -*- coding: utf-8 -*-
# @Time    : 2020/12/30 00:21:10
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : rtfparser.py
# @Software: Visual Studio Code


import logging

from mmpi.common.abstracts import Processing
from mmpi.common.exceptions import ProcessingError
from mmpi.common.rtfextract import process


log = logging.getLogger(__name__)


class RTFParser(Processing):

    @classmethod
    def init_once(cls):
        log.debug("Initializing RTFParser...")

        try:
            # nothing to do
            pass
        except Exception as e:
            raise ProcessingError(
                "There was a syntax error in one or more RTFParser: %s" % e
            )

    def run(self):
        self.key = "rtf"
        if self.key == self.file_type:
            rtf = {'rtf': list()}
            info = {'infos': list(), 'datas': list(), 'report': rtf}

            if self.file_content:
                # magic_type = get_magic_type(self.file_content)
                try:
                    datas = process(self.file_content)
                    rtf['rtf'] = datas
                    info['infos'] = datas
                    if info.get('infos', []) or info.get('datas', []) or rtf.get('rtf', {}):
                        return info
                except Exception as e:
                    pass
        return None
