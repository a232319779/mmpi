# -*- coding: utf-8 -*-
# @Time    : 2020/12/18 22:03:03 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : misc.py 
# @Software: Visual Studio Code


import importlib
import logging
import os
import sys
import types
import mmpi

log = logging.getLogger(__name__)


def cwd(*args):
    """Returns absolute path to this file in the  Working Directory."""
    return os.path.join(os.path.dirname(__file__), *args)


def mkdir(*args):
    """Create a directory without throwing exceptions if it already exists."""
    dirpath = os.path.join(*args)
    if not os.path.isdir(dirpath):
        os.mkdir(dirpath)


def load_signatures():
    sys.modules["data_lib"] = types.ModuleType("data_lib")
    sys.modules["data_lib.mmpi"] = sys.modules["mmpi"]
    sys.modules["data_lib.mmpi.common"] = sys.modules["mmpi.common"]

    # Import this here in order to avoid recursive import statements.
    from mmpi.common.abstracts import Signature

    # Define Signature in such a way that it is equal to "our" Signature.
    sys.modules["data_lib.mmpi.common.abstracts"] = types.ModuleType(
        "data_lib.mmpi.common.abstracts"
    )
    sys.modules["data_lib.mmpi.common.abstracts"].Signature = Signature
    # Don't clobber the Working Directory with .pyc files.
    dont_write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True

    sys.path.insert(0, cwd("data"))
    mod = importlib.import_module("signatures")
    sys.path.pop(0)

    # Restore bytecode option.
    sys.dont_write_bytecode = dont_write_bytecode

    # Index all of the available Signatures that have been located.
    for key, value in sorted(mod.__dict__.items()):
        if not key.startswith("_") and hasattr(value, "plugins"):
            mmpi.signatures.extend(value.plugins)
