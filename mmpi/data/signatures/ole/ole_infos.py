# -*- coding: utf-8 -*-
# @Time    : 2020/12/27 18:09:15 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : ole_infos.py 
# @Software: Visual Studio Code


from data_lib.mmpi.common.abstracts import Signature


class OleTypeNotMatch(Signature):
    authors = ["ddvv"]
    sig_type = 'ole'
    name = "ole_type_not_match"
    severity = 3
    description = "Ole Type Not Match"

    def on_complete(self):
        results = self.get_results()
        for result in results:
            if result.get('type', '') == self.sig_type:
                infos = result.get('value', {}).get('infos', [])
                for info in infos:
                    o_type = info.get('type')
                    m_type = info.get('magic_type')
                    if o_type != m_type:
                        self.mark(type="ole", tag=self.name, o_type=o_type, m_type=m_type)
                return self.has_marks()
        return None