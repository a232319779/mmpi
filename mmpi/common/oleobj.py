
# -*- coding: utf-8 -*-
# @Time    :   2020/12/20 00:53:36
# @Author  :   ddvv
# @Site    :   https://www.cnblogs.com/ddvv
# @File    :   oleobj.py
# @Software:   Visual Studio Code
# @Desc    :   None

"""
oleobj.py

oleobj is a Python script and module to parse OLE objects and files stored
into various MS Office file formats (doc, xls, ppt, docx, xlsx, pptx, etc)

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

oleobj is part of the python-oletools package:
http://www.decalage.info/python/oletools
"""

# === LICENSE =================================================================

# oleobj is copyright (c) 2015-2020 Philippe Lagadec (http://www.decalage.info)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


# -- IMPORTS ------------------------------------------------------------------

from __future__ import print_function

import logging
import struct
import os
import sys
from zipfile import is_zipfile


# IMPORTANT: it should be possible to run oletools directly as scripts
# in any directory without installing them with pip or setup.py.
# In that case, relative imports are NOT usable.
# And to enable Python 2+3 compatibility, we need to use absolute imports,
# so we add the oletools parent folder to sys.path (absolute+normalized path):
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
# print('_thismodule_dir = %r' % _thismodule_dir)
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
# print('_parent_dir = %r' % _thirdparty_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

# -----------------------------------------------------------------------------
# CHANGELOG:
# 2015-12-05 v0.01 PL: - first version
# 2016-06          PL: - added main and process_file (not working yet)
# 2016-07-18 v0.48 SL: - added Python 3.5 support
# 2016-07-19       PL: - fixed Python 2.6-7 support
# 2016-11-17 v0.51 PL: - fixed OLE native object extraction
# 2016-11-18       PL: - added main for setup.py entry point
# 2017-05-03       PL: - fixed absolute imports (issue #141)
# 2018-01-18 v0.52 CH: - added support for zipped-xml-based types (docx, pptx,
#                        xlsx), and ppt
# 2018-03-27       PL: - fixed issue #274 in read_length_prefixed_string
# 2018-09-11 v0.54 PL: - olefile is now a dependency
# 2018-10-30       SA: - added detection of external links (PR #317)
# 2020-03-03 v0.56 PL: - fixed bug #541, "Ole10Native" is case-insensitive

__version__ = '0.56'

# -----------------------------------------------------------------------------
# TODO:
# + setup logging (common with other oletools)


# -----------------------------------------------------------------------------
# REFERENCES:

# Reference for the storage of embedded OLE objects/files:
# [MS-OLEDS]: Object Linking and Embedding (OLE) Data Structures
# https://msdn.microsoft.com/en-us/library/dd942265.aspx

# - officeparser: https://github.com/unixfreak0037/officeparser
# TODO: oledump


# === LOGGING =================================================================

DEFAULT_LOG_LEVEL = "warning"
LOG_LEVELS = {'debug':    logging.DEBUG,
              'info':     logging.INFO,
              'warning':  logging.WARNING,
              'error':    logging.ERROR,
              'critical': logging.CRITICAL,
              'debug-olefile': logging.DEBUG}


class NullHandler(logging.Handler):
    """
    Log Handler without output, to avoid printing messages if logging is not
    configured by the main application.
    Python 2.7 has logging.NullHandler, but this is necessary for 2.6:
    see https://docs.python.org/2.6/library/logging.html section
    configuring-logging-for-a-library
    """
    def emit(self, record):
        pass


def get_logger(name, level=logging.CRITICAL+1):
    """
    Create a suitable logger object for this module.
    The goal is not to change settings of the root logger, to avoid getting
    other modules' logs on the screen.
    If a logger exists with same name, reuse it. (Else it would have duplicate
    handlers and messages would be doubled.)
    The level is set to CRITICAL+1 by default, to avoid any logging.
    """
    # First, test if there is already a logger with the same name, else it
    # will generate duplicate messages (due to duplicate handlers):
    if name in logging.Logger.manager.loggerDict:
        # NOTE: another less intrusive but more "hackish" solution would be to
        # use getLogger then test if its effective level is not default.
        logger = logging.getLogger(name)
        # make sure level is OK:
        logger.setLevel(level)
        return logger
    # get a new logger:
    logger = logging.getLogger(name)
    # only add a NullHandler for this logger, it is up to the application
    # to configure its own logging:
    logger.addHandler(NullHandler())
    logger.setLevel(level)
    return logger


# a global logger object used for debugging:
log = get_logger('oleobj')     # pylint: disable=invalid-name


def enable_logging():
    """
    Enable logging for this module (disabled by default).
    This will set the module-specific logger level to NOTSET, which
    means the main application controls the actual logging level.
    """
    log.setLevel(logging.NOTSET)


# === CONSTANTS ===============================================================

# some str methods on Python 2.x return characters,
# while the equivalent bytes methods return integers on Python 3.x:
if sys.version_info[0] <= 2:
    # Python 2.x
    NULL_CHAR = '\x00'
else:
    # Python 3.x
    NULL_CHAR = 0     # pylint: disable=redefined-variable-type
    xrange = range    # pylint: disable=redefined-builtin, invalid-name

OOXML_RELATIONSHIP_TAG = '{http://schemas.openxmlformats.org/package/2006/relationships}Relationship'

# === GLOBAL VARIABLES ========================================================

# struct to parse an unsigned integer of 32 bits:
STRUCT_UINT32 = struct.Struct('<L')
assert STRUCT_UINT32.size == 4  # make sure it matches 4 bytes

# struct to parse an unsigned integer of 16 bits:
STRUCT_UINT16 = struct.Struct('<H')
assert STRUCT_UINT16.size == 2  # make sure it matches 2 bytes

# max length of a zero-terminated ansi string. Not sure what this really is
STR_MAX_LEN = 1024

# size of chunks to copy from ole stream to file
DUMP_CHUNK_SIZE = 4096

# return values from main; can be added
# (e.g.: did dump but had err parsing and dumping --> return 1+4+8 = 13)
RETURN_NO_DUMP = 0     # nothing found to dump/extract
RETURN_DID_DUMP = 1    # did dump/extract successfully
RETURN_ERR_ARGS = 2    # reserve for OptionParser.parse_args
RETURN_ERR_STREAM = 4  # error opening/parsing a stream
RETURN_ERR_DUMP = 8    # error dumping data from stream to file

# Not sure if they can all be "External", but just in case
BLACKLISTED_RELATIONSHIP_TYPES = [
    'attachedTemplate',
    'externalLink',
    'externalLinkPath',
    'externalReference'
    'frame'
    'hyperlink',
    'officeDocument',
    'oleObject',
    'package',
    'slideUpdateUrl',
    'slideMaster',
    'slide',
    'slideUpdateInfo',
    'subDocument',
    'worksheet'
]

# === FUNCTIONS ===============================================================


def read_uint32(data, index):
    """
    Read an unsigned integer from the first 32 bits of data.

    :param data: bytes string or stream containing the data to be extracted.
    :param index: index to start reading from or None if data is stream.
    :return: tuple (value, index) containing the read value (int),
             and the index to continue reading next time.
    """
    if index is None:
        value = STRUCT_UINT32.unpack(data.read(4))[0]
    else:
        value = STRUCT_UINT32.unpack(data[index:index+4])[0]
        index += 4
    return (value, index)


def read_uint16(data, index):
    """
    Read an unsigned integer from the 16 bits of data following index.

    :param data: bytes string or stream containing the data to be extracted.
    :param index: index to start reading from or None if data is stream
    :return: tuple (value, index) containing the read value (int),
             and the index to continue reading next time.
    """
    if index is None:
        value = STRUCT_UINT16.unpack(data.read(2))[0]
    else:
        value = STRUCT_UINT16.unpack(data[index:index+2])[0]
        index += 2
    return (value, index)


def read_length_prefixed_string(data, index):
    """
    Read a length-prefixed ANSI string from data.

    :param data: bytes string or stream containing the data to be extracted.
    :param index: index in data where string size start or None if data is
                  stream
    :return: tuple (value, index) containing the read value (bytes string),
             and the index to start reading from next time.
    """
    length, index = read_uint32(data, index)
    # if length = 0, return a null string (no null character)
    if length == 0:
        return ('', index)
    # extract the string without the last null character
    if index is None:
        ansi_string = data.read(length-1)
        null_char = data.read(1)
    else:
        ansi_string = data[index:index+length-1]
        null_char = data[index+length-1]
        index += length
    # TODO: only in strict mode:
    # check the presence of the null char:
    assert null_char == NULL_CHAR
    return (ansi_string, index)


def guess_encoding(data):
    """ guess encoding of byte string to create unicode

    Since this is used to decode path names from ole objects, prefer latin1
    over utf* codecs if ascii is not enough
    """
    for encoding in 'ascii', 'latin1', 'utf8', 'utf-16-le', 'utf16':
        try:
            result = data.decode(encoding, errors='strict')
            log.debug(u'decoded using {0}: "{1}"'.format(encoding, result))
            return result
        except UnicodeError:
            pass
    log.warning('failed to guess encoding for string, falling back to '
                'ascii with replace')
    return data.decode('ascii', errors='replace')


def read_zero_terminated_string(data, index):
    """
    Read a zero-terminated string from data

    :param data: bytes string or stream containing an ansi string
    :param index: index at which the string should start or None if data is
                  stream
    :return: tuple (unicode, index) containing the read string (unicode),
             and the index to start reading from next time.
    """
    if index is None:
        result = bytearray()
        for _ in xrange(STR_MAX_LEN):
            char = ord(data.read(1))    # need ord() for py3
            if char == 0:
                return guess_encoding(result), index
            result.append(char)
        raise ValueError('found no string-terminating zero-byte!')
    else:       # data is byte array, can just search
        end_idx = data.index(b'\x00', index, index+STR_MAX_LEN)
        # encode and return with index after the 0-byte
        return guess_encoding(data[index:end_idx]), end_idx+1


# === CLASSES =================================================================


class OleNativeStream(object):
    """
    OLE object contained into an OLENativeStream structure.
    (see MS-OLEDS 2.3.6 OLENativeStream)

    Filename and paths are decoded to unicode.
    """
    # constants for the type attribute:
    # see MS-OLEDS 2.2.4 ObjectHeader
    TYPE_LINKED = 0x01
    TYPE_EMBEDDED = 0x02

    def __init__(self, bindata=None, package=False):
        """
        Constructor for OleNativeStream.
        If bindata is provided, it will be parsed using the parse() method.

        :param bindata: forwarded to parse, see docu there
        :param package: bool, set to True when extracting from an OLE Package
                        object
        """
        self.filename = None
        self.src_path = None
        self.unknown_short = None
        self.unknown_long_1 = None
        self.unknown_long_2 = None
        self.temp_path = None
        self.actual_size = None
        self.data = None
        self.package = package
        self.is_link = None
        self.data_is_stream = None
        if bindata is not None:
            self.parse(data=bindata)

    def parse(self, data):
        """
        Parse binary data containing an OLENativeStream structure,
        to extract the OLE object it contains.
        (see MS-OLEDS 2.3.6 OLENativeStream)

        :param data: bytes array or stream, containing OLENativeStream
                     structure containing an OLE object
        :return: None
        """
        # TODO: strict mode to raise exceptions when values are incorrect
        # (permissive mode by default)
        if hasattr(data, 'read'):
            self.data_is_stream = True
            index = None       # marker for read_* functions to expect stream
        else:
            self.data_is_stream = False
            index = 0          # marker for read_* functions to expect array

        # An OLE Package object does not have the native data size field
        if not self.package:
            self.native_data_size, index = read_uint32(data, index)
            log.debug('OLE native data size = {0:08X} ({0} bytes)'
                      .format(self.native_data_size))
        # I thought this might be an OLE type specifier ???
        self.unknown_short, index = read_uint16(data, index)
        self.filename, index = read_zero_terminated_string(data, index)
        # source path
        self.src_path, index = read_zero_terminated_string(data, index)
        # TODO: I bet these 8 bytes are a timestamp ==> FILETIME from olefile
        self.unknown_long_1, index = read_uint32(data, index)
        self.unknown_long_2, index = read_uint32(data, index)
        # temp path?
        self.temp_path, index = read_zero_terminated_string(data, index)
        # size of the rest of the data
        try:
            self.actual_size, index = read_uint32(data, index)
            if self.data_is_stream:
                self.data = data
            else:
                self.data = data[index:index+self.actual_size]
            self.is_link = False
            # TODO: there can be extra data, no idea what it is for
            # TODO: SLACK DATA
        except (IOError, struct.error):      # no data to read actual_size
            log.debug('data is not embedded but only a link')
            self.is_link = True
            self.actual_size = 0
            self.data = None


class OleObject(object):
    """
    OLE 1.0 Object

    see MS-OLEDS 2.2 OLE1.0 Format Structures
    """

    # constants for the format_id attribute:
    # see MS-OLEDS 2.2.4 ObjectHeader
    TYPE_LINKED = 0x01
    TYPE_EMBEDDED = 0x02

    def __init__(self, bindata=None):
        """
        Constructor for OleObject.
        If bindata is provided, it will be parsed using the parse() method.

        :param bindata: bytes, OLE 1.0 Object structure containing OLE object

        Note: Code can easily by generalized to work with byte streams instead
              of arrays just like in OleNativeStream.
        """
        self.ole_version = None
        self.format_id = None
        self.class_name = None
        self.topic_name = None
        self.item_name = None
        self.data = None
        self.data_size = None
        if bindata is not None:
            self.parse(bindata)

    def parse(self, data):
        """
        Parse binary data containing an OLE 1.0 Object structure,
        to extract the OLE object it contains.
        (see MS-OLEDS 2.2 OLE1.0 Format Structures)

        :param data: bytes, OLE 1.0 Object structure containing an OLE object
        :return:
        """
        # from ezhexviewer import hexdump3
        # print("Parsing OLE object data:")
        # print(hexdump3(data, length=16))
        # Header: see MS-OLEDS 2.2.4 ObjectHeader
        index = 0
        self.ole_version, index = read_uint32(data, index)
        self.format_id, index = read_uint32(data, index)
        log.debug('OLE version=%08X - Format ID=%08X',
                  self.ole_version, self.format_id)
        assert self.format_id in (self.TYPE_EMBEDDED, self.TYPE_LINKED)
        self.class_name, index = read_length_prefixed_string(data, index)
        self.topic_name, index = read_length_prefixed_string(data, index)
        self.item_name, index = read_length_prefixed_string(data, index)
        log.debug('Class name=%r - Topic name=%r - Item name=%r',
                  self.class_name, self.topic_name, self.item_name)
        if self.format_id == self.TYPE_EMBEDDED:
            # Embedded object: see MS-OLEDS 2.2.5 EmbeddedObject
            # assert self.topic_name != '' and self.item_name != ''
            self.data_size, index = read_uint32(data, index)
            log.debug('Declared data size=%d - remaining size=%d',
                      self.data_size, len(data)-index)
            # TODO: handle incorrect size to avoid exception
            self.data = data[index:index+self.data_size]
            assert len(self.data) == self.data_size
            self.extra_data = data[index+self.data_size:]
