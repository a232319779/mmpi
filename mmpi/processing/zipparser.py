# -*- coding: utf-8 -*-
# @Time    : 2020/12/20 16:40:55
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : zipparser.py
# @Software: Visual Studio Code


import logging
from hashlib import md5, sha1
from zipfile import ZipFile
from io import BytesIO

from mmpi.common.abstracts import Processing
from mmpi.common.exceptions import ProcessingError


log = logging.getLogger(__name__)


class ZipParser(Processing):

    @classmethod
    def init_once(cls):
        log.debug("Initializing ZipParser...")

        try:
            # nothing to do
            pass
        except Exception as e:
            raise ProcessingError(
                "There was a syntax error in one or more ZipParser: %s" % e
            )
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

    @classmethod
    def check_office(cls, data):
        if '[Content_Types].xml' in data:
        # if 'word/_rels/settings.xml.rels' in data:
            return True
        return False

    def parse_zip(self, z, info):
        names = z.namelist()
        for name in names:
            z_info = z.getinfo(name)
            if z_info.is_dir():
                info['infos'].append({'name': name, 'type': 'dir'})
            else:
                file_type = name.split('.')[-1]
                info['infos'].append({'name': name, 'type': file_type})
                content = z.read(name)
                info['datas'].append({'file_type': file_type, 'filename': name, 'filesize': z_info.file_size, 'content': content})
                file_md5 = self.calc_md5(content)
                file_sha1 = self.calc_sha1(content)
                info['report']['zip'].append({'type': file_type, 'filename': name, 'filesize': z_info.file_size, 'md5': file_md5, 'sha1': file_sha1})

    def parse_office(self, z, info):
        key_names = ['word/_rels/settings.xml.rels']
        names = z.namelist()
        for name in names:
            if name in key_names or name.endswith('.bin'):
                z_info = z.getinfo(name)
                file_type = name.split('.')[-1]
                if file_type == 'bin':
                    file_type = 'ole'
                content = z.read(name)
                info['datas'].append({'file_type': file_type, 'filename': name, 'filesize': z_info.file_size, 'content': content})
                file_md5 = self.calc_md5(content)
                file_sha1 = self.calc_sha1(content)
                info['report']['zip'].append({'type': file_type, 'filename': name, 'filesize': z_info.file_size, 'md5': file_md5, 'sha1': file_sha1})

    def run(self):
        self.key = "zip"
        if self.key == self.file_type:
            zip_info = {'zip': list()}
            info = {'infos': list(), 'datas': list(), 'report': zip_info}

            if self.file_content:
                zip_io = BytesIO(self.file_content)
                try:
                    z = ZipFile(zip_io, 'r')
                    if self.check_office(z.namelist()):
                        self.parse_office(z, info)
                    else:
                        self.parse_zip(z, info)
                    z.close()
                    if info.get('infos', []) or info.get('datas', []):
                        return info
                except Exception as e:
                    info['infos'].append({'message': str(e)})
                    return info
        return None
