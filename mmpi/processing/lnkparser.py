# -*- coding: utf-8 -*-
# @Time    : 2021/01/13 23:00:10 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : lnkparser.py 
# @Software: Visual Studio Code


import logging

from mmpi.common.abstracts import Processing
from mmpi.common.exceptions import ProcessingError
from mmpi.common.lnk import lnk_file


log = logging.getLogger(__name__)


class LnkParser(Processing):

    @classmethod
    def init_once(cls):
        log.debug("Initializing LnkParser...")

        try:
            # nothing to do
            pass
        except Exception as e:
            raise ProcessingError(
                "There was a syntax error in one or more LnkParser: %s" % e
            )

    def run(self):
        self.key = "lnk"
        if self.key == self.file_type:
            lnk_report = {'lnk': list()}
            info = {'infos': list(), 'datas': list(), 'report': lnk_report}

            if self.file_content:
                try:
                    lf = lnk_file(indata=self.file_content)
                    if lf.is_lnk_file():
                        lf_json = lf.get_json()
                        data = lf_json.get('data')
                        if data:
                            info['infos'].append({'file_type': 'lnk', 'data': data})
                            lnk_report['lnk'].append(
                                {'size': len(data), 'data': data})
                    if info.get('infos', []) or info.get('datas', []):
                        return info
                except Exception as e:
                    pass
        return None
