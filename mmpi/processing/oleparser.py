# -*- coding: utf-8 -*-
# @Time    : 2020/12/21 21:13:06
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : oleparser.py
# @Software: Visual Studio Code


import logging

from mmpi.common.abstracts import Processing
from mmpi.common.exceptions import ProcessingError
from mmpi.common.olevba import VBA_RUN
# from mmpi.common.filetypes import get_magic_type


log = logging.getLogger(__name__)


class OleParser(Processing):

    @classmethod
    def init_once(cls):
        log.debug("Initializing OleParser...")

        try:
            # nothing to do
            cls.vr = VBA_RUN()
        except Exception as e:
            raise ProcessingError(
                "There was a syntax error in one or more OleParser: %s" % e
            )

    def run(self):
        self.key = "ole"
        if self.key == self.file_type:
            vba = {'vba': list()}
            info = {'infos': list(), 'datas': list(), 'report': vba}

            if self.file_content:
                # magic_type = get_magic_type(self.file_content)
                try:
                    if self.vr.is_ole(self.file_content):
                        for data in self.vr.parse(self.file_content):
                            vba_code = data.get('vba_code')
                            info['datas'].append({'file_type': 'vba', 'filename': data.get(
                                'vba_filename'), 'filesize': len(vba_code), 'content': vba_code})
                            vba['vba'].append(
                                {'size': len(vba_code), 'code': vba_code.decode()})
                    else:
                        # maybe rtf
                        info['datas'].append(
                            {'file_type': 'rtf', 'content': self.file_content})
                    if info.get('infos', []) or info.get('datas', []):
                        return info
                except Exception as e:
                    # magic_type = get_magic_type(self.file_content)
                    magic_type = ''
                    info['infos'].append(
                        {'type': self.file_type, 'magic_type': magic_type})
                    return info
        return None
