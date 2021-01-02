# -*- coding: utf-8 -*-
# @Time    : 2020/12/19 11:43:03
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : emailparser.py
# @Software: Visual Studio Code


import logging
from datetime import datetime
from hashlib import md5, sha1
from email.message import Message
from email.parser import BytesParser
from email.header import decode_header, Header
from email._parseaddr import AddressList as _AddressList
from email.utils import parsedate_to_datetime

from mmpi.common.abstracts import Processing
from mmpi.common.exceptions import ProcessingError
# from mmpi.common.filetypes import get_magic_type


log = logging.getLogger(__name__)


class EmailParser(Processing):

    @classmethod
    def init_once(cls):
        log.debug("Initializing EmailParser...")

        try:
            cls.ep = BytesParser()
        except Exception as e:
            raise ProcessingError(
                "There was a syntax error in one or more EmailParser: %s" % e
            )

    @classmethod
    def guess_charset(cls, msg):
        charset = msg.get_charset()
        if charset is None:
            content_type = msg.get('Content-Type', '').lower()
            content_type = content_type.replace('"', '')
            pos = content_type.find('charset=')
            if pos >= 0:
                charset = content_type[pos+8:].split(';')[0].strip()
        if charset is None:
            charset = 'utf8'
        if charset == 'cp-850':
            charset = 'cp850'
        return charset

    @classmethod
    def decode_str(cls, s):
        value, charset = decode_header(s)[0]
        if charset:
            if 'utf-8' in charset:
                charset = 'utf-8'
            try:
                value = value.decode(charset, 'ignore')
            except LookupError as e:
                value = value.decode('utf-8', 'ignore')
        return value

    @classmethod
    def calc_md5(cls, data): #计算md5
        data_md5 = md5()
        data_md5.update(data)
        return data_md5.hexdigest()
    
    @classmethod
    def calc_sha1(cls, data): #计算md5
        data_sha1 = sha1()
        data_sha1.update(data)
        return data_sha1.hexdigest()

    def parse_eml_obj(self, emlmsg, info):
        for part in emlmsg.walk():
            if part.get('From'):
                sender = part.get('From')
                sender_list = list()
                recv_list = list()
                subject_text = '', '', '', '', ''
                if isinstance(sender, Header):
                    addrs = _AddressList(sender.__str__()).addresslist
                    for addr in addrs:
                        sender_list.append({'name': self.decode_str(addr[0]), 'addr': addr[1]})
                elif isinstance(sender, str):
                    addrs = _AddressList(sender).addresslist
                    for addr in addrs:
                        sender_list.append({'name': self.decode_str(addr[0]), 'addr': addr[1]})
                to = part.get('To')
                if isinstance(to, Header):
                    addrs = _AddressList(to.__str__()).addresslist
                    for addr in addrs:
                        recv_list.append({'name': self.decode_str(addr[0]), 'addr': addr[1]})
                elif isinstance(to, str):
                    addrs = _AddressList(to).addresslist
                    for addr in addrs:
                        recv_list.append({'name': self.decode_str(addr[0]), 'addr': addr[1]})
                o_date = part.get('Date')
                date = datetime.strptime('1949-10-01 10:08:22', "%Y-%y-%d %H:%M:%S")
                if o_date:
                    try:
                        date = parsedate_to_datetime(o_date)
                    except Exception as e:
                        pass
                X_Originating_IP = part.get('X-Originating-IP')
                if X_Originating_IP:
                    tmp = X_Originating_IP.split(',')
                    tmp[0] = tmp[0][1:]
                    tmp[-1] = tmp[-1][:-1]
                    X_Originating_IP = tmp
                else:
                    X_Originating_IP = []
                subject = part.get('Subject')
                if isinstance(subject, Header):
                    subject_text = self.decode_str(subject.__str__())
                elif isinstance(subject, str):
                    subject_text = self.decode_str(subject)
                header = {'From': sender_list, 'To': recv_list, 'Subject': subject_text, 'Date': date.strftime('%Y-%m-%d %H:%M:%S %Z'), 'X-Originating-IP': X_Originating_IP}
                info['infos'].append(header)
                info['report']['headers'].append(header)
            content_type = part.get('Content-Type')
            if content_type:
                if isinstance(content_type, Header):
                    content_type = content_type.__str__()
                content_type = content_type.lower()
                if content_type.startswith('text/plain'):
                    try:
                        charset = self.guess_charset(part)
                        content = part.get_payload(
                            decode=True).decode(charset, "ignore")
                    except Exception as e:
                        content = part.get_payload()
                    info['datas'].append(
                        {'file_type': 'text', 'content': content})
                    info['report']['body'].append(
                        {'type': 'text', 'content': content})
                elif content_type.startswith('text/html'):
                    try:
                        charset = self.guess_charset(part)
                        content = part.get_payload(
                            decode=True).decode(charset, "ignore")
                    except Exception as e:
                        content = part.get_payload()
                    info['datas'].append(
                        {'file_type': 'html', 'content': content})
            cdispo = part.get('Content-Disposition')
            if cdispo:
                if isinstance(cdispo, Header):
                    cdispo = cdispo.__str__()
                cdispo = cdispo.lower()
                if cdispo.startswith('attachment'):
                    try:
                        # Here is the logic table for this code, based on the email5.0.0 code:
                        #   i     decode  is_multipart  result
                        # ------  ------  ------------  ------------------------------
                        #  None   True    True          None    *
                        #   i     True    True          None
                        #  None   False   True          _payload (a list)
                        #   i     False   True          _payload element i (a Message)
                        #   i     False   False         error (not a list)
                        #   i     True    False         error (not a list)
                        #  None   False   False         _payload
                        #  None   True    False         _payload decoded (bytes) *
                        # in mmpi, just two way use it, marked as *
                        content = part.get_payload(decode=True)
                        if content:
                            attachment_name = part.get_filename()
                            if attachment_name:
                                name = self.decode_str(attachment_name)
                                file_type = name.split('.')[-1]
                                info['datas'].append({'file_type': file_type, 'filename': name, 'filesize': len(content), 'content': content})
                                file_md5 = self.calc_md5(content)
                                file_sha1 = self.calc_sha1(content)
                                # magic_tyep = get_magic_type(content)
                                info['report']['attachments'].append({'type': file_type, 'filename': name, 'filesize': len(content), 'md5': file_md5, 'sha1': file_sha1})
                            else:
                                try:
                                    tmp_msg = self.ep.parsebytes(content)
                                    self.parse_eml_obj(tmp_msg, info)
                                except Exception as e:
                                    log.error(e)
                        else:
                            # if type is eml, something to do
                            contents = part.get_payload()
                            if contents:
                                for content in contents:
                                    if isinstance(content, Message):
                                        self.parse_eml_obj(content, info)
                    except Exception as e:
                        log.error(e)
                        continue


    def run(self):
        self.key = "eml"
        if self.key == self.file_type:
            report = {"headers": list(), "body": list(), "attachments": list()}
            info = {'infos': list(), 'datas': list(), 'report': report}

            if self.file_content:
                emlmsg = self.ep.parsebytes(self.file_content)
                self.parse_eml_obj(emlmsg, info)
            if info.get('infos', []) or info.get('datas', []):
                return info
        return None
