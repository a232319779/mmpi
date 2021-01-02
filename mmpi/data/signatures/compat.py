# -*- coding: utf-8 -*-
# @Time    : 2020/12/23 01:58:57 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : compat.py 
# @Software: Visual Studio Code


def enumerate_signatures(dirpath, submodule, g, attributes):
    """In the new Cuckoo package, Signatures are no longer accessed
    under the modules module."""
    try:
        from mmpi.core.plugins import enumerate_plugins
        from mmpi.common.abstracts import Signature

        return enumerate_plugins(
            dirpath, "signatures.%s" % submodule,
            g, Signature, attributes
        )
    except ImportError:
        from mmpi.core.plugins import enumerate_plugins
        from mmpi.common.abstracts import Signature

        return enumerate_plugins(
            dirpath, "modules.signatures.%s" % submodule,
            g, Signature, attributes
        )
