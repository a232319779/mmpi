# -*- coding: utf-8 -*-
# @Time    : 2020/12/20 19:25:41 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : otherparser.py 
# @Software: Visual Studio Code


import logging
import os
try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

from mmpi.common.abstracts import Processing
from mmpi.misc import cwd
from mmpi.common.exceptions import ProcessingError
from mmpi.common.filetypes import OTHER_LIST

log = logging.getLogger(__name__)


class OtherParser(Processing):

    yara_rules = {}

    @classmethod
    def init_once(cls):
        if not HAVE_YARA:
            cls.enabled = False
            log.warning("YaraScanner need yara-python module, please install. pip install yara-python")
            return None
        log.debug("Initializing Yara...")

        yara_rules_path = cwd("data", "yara")

        categories = os.listdir(yara_rules_path)

        for category in categories:
            dirpath = cwd(yara_rules_path, category)
            if not os.path.exists(dirpath):
                log.warning("Missing Yara directory: %s?", dirpath)

            rules, indexed = {}, []
            for dirpath, dirnames, filenames in os.walk(dirpath, followlinks=True):
                for filename in filenames:
                    if not filename.endswith((".yar", ".yara")):
                        continue

                    filepath = os.path.join(dirpath, filename)
                    try:
                        # TODO Once Yara obtains proper Unicode filepath support we
                        # can remove this check. See also this Github issue:
                        # https://github.com/VirusTotal/yara-python/issues/48
                        assert len(str(filepath)) == len(filepath)
                    except (UnicodeEncodeError, AssertionError):
                        log.warning(
                            "Can't load Yara rules at %r as Unicode filepaths are "
                            "currently not supported in combination with Yara!",
                            filepath
                        )
                        continue

                    rules["rule_%s_%d" % (category, len(rules))] = filepath
                    indexed.append(filename)

                    try:
                        OtherParser.yara_rules[category] = yara.compile(
                            filepaths=rules
                        )
                    except yara.Error as e:
                        raise ProcessingError(
                            "There was a syntax error in one or more Yara rules: %s" % e
                        )

                indexed = sorted(indexed)
                for entry in indexed:
                    if (category, entry) == indexed[-1]:
                        log.debug("\t `-- %s %s", category, entry)
                    else:
                        log.debug("\t |-- %s %s", category, entry)

    def run(self):
        self.key = self.file_type
        if self.file_type in OTHER_LIST:
            if self.file_content:
                info = {'infos': list(), 'datas': list()}
                for category, rule in OtherParser.yara_rules.items():
                    if category == self.file_type:
                        matchs = rule.match(data=self.file_content)
                        if matchs:
                            for match in matchs:
                                meta = {
                                    "name": match.meta.get('name'),
                                    "description": match.meta.get('description'),
                                    "severity": match.meta.get('severity'),
                                    "type": match.meta.get('type')
                                }
                                info['infos'].append(meta)

                if info.get('infos', []) or info.get('datas', []):
                    return info
        return None