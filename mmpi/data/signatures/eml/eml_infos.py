# -*- coding: utf-8 -*-
# @Time    : 2020/12/20 16:25:38 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : eml_infos.py 
# @Software: Visual Studio Code


from data_lib.mmpi.common.abstracts import Signature


MALICIOUS_SENDERS = [
]


class MaliciousSender(Signature):
    authors = ["ddvv"]
    sig_type = 'eml'
    name = "malicious_sender"
    severity = 6
    description = "malicious sender mail box"

    def on_complete(self):
        results = self.get_results()
        for result in results:
            if result.get('type', '') == self.sig_type:
                infos = result.get('value', {}).get('infos', [])
                for info in infos:
                    addrs  = info.get('From', [])
                    for addr in addrs:
                        mailbox = addr.get('addr', '')
                        if mailbox in MALICIOUS_SENDERS:
                            self.mark(type="eml", tag=self.name, data=mailbox)
                            return self.has_marks()
        return None
