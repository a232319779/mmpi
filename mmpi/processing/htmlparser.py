# -*- coding: utf-8 -*-
# @Time    : 2020/12/20 10:58:06 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : htmlparser.py 
# @Software: Visual Studio Code


import logging

from html.parser import HTMLParser
from urllib.parse import unquote

from mmpi.common.abstracts import Processing
from mmpi.common.exceptions import ProcessingError


log = logging.getLogger(__name__)


class MMHtmlParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.result = list()
        self.bingo = False
        self.is_a = False
        self.__url__ = ''

    def is_bingo(self):
        return self.bingo

    def get_result(self):
        return self.result

    @classmethod
    def __parse_img__(cls, attrs):
        img = {'src': '', 'width': 9999, 'height': 9999}
        for attr in attrs:
            if 'src' == attr[0]:
                src = unquote(attr[1])
                if 'http' not in src:
                    return None
                img[attr[0]] = src
            elif 'width' == attr[0]:
                s = ''.join(filter(str.isdigit, attr[1]))
                if s:
                    img[attr[0]] = int(s)
            elif 'height' == attr[0]:
                s = ''.join(filter(str.isdigit, attr[1]))
                if s:
                    img[attr[0]] = int(s)
            elif 'style' == attr[0]:
                if len(attr[1]) == 0:
                    img['width'] = 0
                    img['height'] = 0
                    continue
                tmps = attr[1].replace(' ', '')
                tmps = tmps.split(';')
                for t in tmps:
                    tmp = t.split(':')
                    if 'width' == tmp[0] and tmp[1] != '':
                        s = ''.join(filter(str.isdigit, tmp[1]))
                        if s:
                            img[tmp[0]] = int(s)
                    if 'height' == tmp[0] and tmp[1] != '':
                        s = ''.join(filter(str.isdigit, tmp[1]))
                        if s:
                            img[tmp[0]] = int(s)
        if img.get('src', ''):
            return img
        return None

    def handle_starttag(self, tag, attrs):
        if tag == 'img':
            img = self.__parse_img__(attrs)
            if img:
                self.bingo = True
                self.result.append({'type': 'img', 'data': img})
        elif tag == 'iframe':
            pass
        # url检测
        elif tag == 'a':
            for attr in attrs:
                if 'href' == attr[0]:
                    href = unquote(attr[1])
                    if href.startswith('http'):
                        self.is_a = True
                        self.__url__ = href
                        self.result.append({'type': 'a', 'data': {'src': href}})

    def handle_data(self, data):
        if self.is_a:
            data = data.strip()
            self.result.append({'type': 'hyperlink', 'data': {'src': self.__url__, 'word': data}})

    def handle_endtag(self, tag):
        if tag == 'a':
            self.is_a = False
            self.__url__ = ''


class HtmlParser(Processing):

    @classmethod
    def init_once(cls):
        log.debug("Initializing HtmlParser...")

        try:
            # cls.hp = MMHtmlParser()
            # nothing to do
            pass
        except Exception as e:
            raise ProcessingError(
                "There was a syntax error in one or more HtmlParser: %s" % e
            )

    def run(self):
        self.key = "html"
        if self.key == self.file_type:
            info = {'infos': list(), 'datas': list()}

            if self.file_content:
                hp = MMHtmlParser()
                if isinstance(self.file_content, bytes):
                    self.file_content = self.file_content.decode('utf8', 'ignore')
                hp.feed(self.file_content)
                infos = hp.get_result()
                if hp.is_bingo():
                    info['infos'].extend(infos)
                if info.get('infos', []) or info.get('datas', []):
                    return info
        return None
