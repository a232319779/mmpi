# -*- coding: utf-8 -*-
# @Time    : 2020/12/23 01:58:17 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : startup.py 
# @Software: Visual Studio Code


import logging
import mmpi
from mmpi.core.plugins import RunSignatures

log = logging.getLogger(__name__)


def init_modules():
    """Initializes plugins."""
    log.debug("Imported modules...")

    # categories = (
    #     "processing", "signatures"
    # )
    categories = (
        "processing",
    )

    # Call the init_once() static method of each plugin/module. If an exception
    # is thrown in that initialization call, then a hard error is appropriate.
    for category in categories:
        for module in mmpi.plugins[category]:
            if module.enabled:
                module.init_once()

    for category in categories:
        log.debug("Imported \"%s\" modules:", category)

        entries = mmpi.plugins[category]
        for entry in entries:
            if entry == entries[-1]:
                log.debug("\t `-- %s", entry.__name__)
            else:
                log.debug("\t |-- %s", entry.__name__)

    RunSignatures.init_once()
