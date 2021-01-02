# -*- coding: utf-8 -*-
# @Time    : 2020/12/30 00:20:49 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : rtfextract.py 
# @Software: Visual Studio Code


from __future__ import print_function

"""
rtfobj.py

rtfobj is a Python module to extract embedded objects from RTF files, such as
OLE ojects. It can be used as a Python library or a command-line tool.

Usage: rtfobj.py <file.rtf>

rtfobj project website: http://www.decalage.info/python/rtfobj

rtfobj is part of the python-oletools package:
http://www.decalage.info/python/oletools
"""

#=== LICENSE =================================================================

# rtfobj is copyright (c) 2012-2019, Philippe Lagadec (http://www.decalage.info)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


#------------------------------------------------------------------------------
# CHANGELOG:
# 2012-11-09 v0.01 PL: - first version
# 2013-04-02 v0.02 PL: - fixed bug in main
# 2015-12-09 v0.03 PL: - configurable logging, CLI options
#                      - extract OLE 1.0 objects
#                      - extract files from OLE Package objects
# 2016-04-01 v0.04 PL: - fixed logging output to use stdout instead of stderr
# 2016-04-07 v0.45 PL: - improved parsing to handle some malware tricks
# 2016-05-06 v0.47 TJ: - added option -d to set the output directory
#                        (contribution by Thomas Jarosch)
#                  TJ: - sanitize filenames to avoid special characters
# 2016-05-29       PL: - improved parsing, fixed issue #42
# 2016-07-13 v0.50 PL: - new RtfParser and RtfObjParser classes
# 2016-07-18       SL: - added Python 3.5 support
# 2016-07-19       PL: - fixed Python 2.6-2.7 support
# 2016-07-30       PL: - new API with class RtfObject
#                      - backward-compatible API rtf_iter_objects (fixed issue #70)
# 2016-07-31       PL: - table output with tablestream
# 2016-08-01       PL: - detect executable filenames in OLE Package
# 2016-08-08       PL: - added option -s to save objects to files
# 2016-08-09       PL: - fixed issue #78, improved regex
# 2016-09-06       PL: - fixed issue #83, backward compatible API
# 2016-11-17 v0.51 PL: - updated call to oleobj.OleNativeStream
# 2017-03-12       PL: - fixed imports for Python 2+3
#                      - fixed hex decoding bug in RtfObjParser (issue #103)
# 2017-03-29       PL: - fixed RtfParser to handle issue #152 (control word with
#                        long parameter)
# 2017-04-11       PL: - added detection of the OLE2Link vulnerability CVE-2017-0199
# 2017-05-04       PL: - fixed issue #164 to handle linked OLE objects
# 2017-06-08       PL: - fixed issue/PR #143: bin object with negative length
# 2017-06-29       PL: - temporary fix for issue #178
# 2017-07-14 v0.52 PL: - disabled logging of each control word (issue #184)
# 2017-07-24       PL: - fixed call to RtfParser._end_of_file (issue #185)
#                      - ignore optional space after \bin (issue #185)
# 2017-09-06       PL: - fixed issue #196: \pxe is not a destination
# 2018-01-11       CH: - speedup RTF parsing (PR #244)
# 2018-02-01      JRM: - fixed issue #251: \bin without argument
# 2018-04-09       PL: - fixed issue #280: OLE Package were not detected on Python 3
# 2018-03-24 v0.53 PL: - fixed issue #292: \margSz is a destination
# 2018-04-27       PL: - extract and display the CLSID of OLE objects
# 2018-04-30       PL: - handle "\'" obfuscation trick - issue #281
# 2018-05-10       PL: - fixed issues #303 #307: several destination cwords were incorrect
# 2018-05-17       PL: - fixed issue #273: bytes constants instead of str
# 2018-05-31 v0.53.1 PP: - fixed issue #316: whitespace after \bin on Python 3
# 2018-06-22 v0.53.2 PL: - fixed issue #327: added "\pnaiu" & "\pnaiud"
# 2018-09-11 v0.54 PL: - olefile is now a dependency
# 2019-07-08 v0.55 MM: - added URL carver for CVE-2017-0199 (Equation Editor) PR #460
#                      - added SCT to the list of executable file extensions PR #461
# 2019-12-16 v0.55.2 PL: - \rtf is not a destination control word (issue #522)
# 2019-12-17         PL: - fixed process_file to detect Equation class (issue #525)

__version__ = '0.55.2'

# ------------------------------------------------------------------------------
# TODO:
# - allow semicolon within hex, as found in  this sample:
#   http://contagiodump.blogspot.nl/2011/10/sep-28-cve-2010-3333-manuscript-with.html
# TODO: use OleObject and OleNativeStream in RtfObject instead of copying each attribute
# TODO: option -e <id> to extract an object, -e all for all objects
# TODO: option to choose which destinations to include (objdata by default)
# TODO: option to display SHA256 or MD5 hashes of objects in table


# === IMPORTS =================================================================

import re, os, sys, binascii, logging, optparse, hashlib
import os.path
from time import time

# IMPORTANT: it should be possible to run oletools directly as scripts
# in any directory without installing them with pip or setup.py.
# In that case, relative imports are NOT usable.
# And to enable Python 2+3 compatibility, we need to use absolute imports,
# so we add the oletools parent folder to sys.path (absolute+normalized path):
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
# print('_thismodule_dir = %r' % _thismodule_dir)
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
# print('_parent_dir = %r' % _thirdparty_dir)
if not _parent_dir in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile
from mmpi.common import oleobj
from mmpi.common import clsid

# === LOGGING =================================================================

class NullHandler(logging.Handler):
    """
    Log Handler without output, to avoid printing messages if logging is not
    configured by the main application.
    Python 2.7 has logging.NullHandler, but this is necessary for 2.6:
    see https://docs.python.org/2.6/library/logging.html#configuring-logging-for-a-library
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
        #NOTE: another less intrusive but more "hackish" solution would be to
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
log = get_logger('rtfobj')


#=== CONSTANTS=================================================================

# REGEX pattern to extract embedded OLE objects in hexadecimal format:

# alphanum digit: [0-9A-Fa-f]
HEX_DIGIT = b'[0-9A-Fa-f]'

# hex char = two alphanum digits: [0-9A-Fa-f]{2}
# HEX_CHAR = r'[0-9A-Fa-f]{2}'
# in fact MS Word allows whitespaces in between the hex digits!
# HEX_CHAR = r'[0-9A-Fa-f]\s*[0-9A-Fa-f]'
# Even worse, MS Word also allows ANY RTF-style tag {*} in between!!
# AND the tags can be nested...
#SINGLE_RTF_TAG = r'[{][^{}]*[}]'
# Actually RTF tags may contain braces escaped with backslash (\{ \}):
SINGLE_RTF_TAG = b'[{](?:\\\\.|[^{}\\\\])*[}]'

# Nested tags, two levels (because Python's re does not support nested matching):
# NESTED_RTF_TAG = r'[{](?:[^{}]|'+SINGLE_RTF_TAG+r')*[}]'
NESTED_RTF_TAG = b'[{](?:\\\\.|[^{}\\\\]|'+SINGLE_RTF_TAG+b')*[}]'

# AND it is also allowed to insert ANY control word or control symbol (ignored)
# According to Rich Text Format (RTF) Specification Version 1.9.1,
# section "Control Word":
# control word = \<ASCII Letter [a-zA-Z] Sequence max 32><Delimiter>
# delimiter = space, OR signed integer followed by any non-digit,
#             OR any character except letter and digit
# examples of valid control words:
# "\AnyThing " "\AnyThing123z" ""\AnyThing-456{" "\AnyThing{"
# control symbol = \<any char except letter or digit> (followed by anything)

ASCII_NAME = b'([a-zA-Z]{1,250})'

# using Python's re lookahead assumption:
# (?=...) Matches if ... matches next, but doesn't consume any of the string.
# This is called a lookahead assertion. For example, Isaac (?=Asimov) will
# match 'Isaac ' only if it's followed by 'Asimov'.

# TODO: Find the actual limit on the number of digits for Word
# SIGNED_INTEGER = r'(-?\d{1,250})'
SIGNED_INTEGER = b'(-?\\d+)'

# Note for issue #78: need to match "\A-" not followed by digits (or the end of string)
CONTROL_WORD = b'(?:\\\\' + ASCII_NAME + b'(?:' + SIGNED_INTEGER + b'(?=[^0-9])|(?=[^a-zA-Z0-9])|$))'

re_control_word = re.compile(CONTROL_WORD)

# Note for issue #78: need to match "\" followed by digit (any non-alpha)
CONTROL_SYMBOL = b'(?:\\\\[^a-zA-Z])'
re_control_symbol = re.compile(CONTROL_SYMBOL)

# Text that is not a control word/symbol or a group:
TEXT = b'[^{}\\\\]+'
re_text = re.compile(TEXT)

# ignored whitespaces and tags within a hex block:
IGNORED = b'(?:\\s|'+NESTED_RTF_TAG+b'|'+CONTROL_SYMBOL+b'|'+CONTROL_WORD+b')*'
#IGNORED = r'\s*'

# HEX_CHAR = HEX_DIGIT + IGNORED + HEX_DIGIT

# several hex chars, at least 4: (?:[0-9A-Fa-f]{2}){4,}
# + word boundaries
# HEX_CHARS_4orMORE = r'\b(?:' + HEX_CHAR + r'){4,}\b'
# at least 1 hex char:
# HEX_CHARS_1orMORE = r'(?:' + HEX_CHAR + r')+'
# at least 1 hex char, followed by whitespace or CR/LF:
# HEX_CHARS_1orMORE_WHITESPACES = r'(?:' + HEX_CHAR + r')+\s+'
# + word boundaries around hex block
# HEX_CHARS_1orMORE_WHITESPACES = r'\b(?:' + HEX_CHAR + r')+\b\s*'
# at least one block of hex and whitespace chars, followed by closing curly bracket:
# HEX_BLOCK_CURLY_BRACKET = r'(?:' + HEX_CHARS_1orMORE_WHITESPACES + r')+\}'
# PATTERN = r'(?:' + HEX_CHARS_1orMORE_WHITESPACES + r')*' + HEX_CHARS_1orMORE

#TODO PATTERN = r'\b(?:' + HEX_CHAR + IGNORED + r'){4,}\b'
# PATTERN = r'\b(?:' + HEX_CHAR + IGNORED + r'){4,}' #+ HEX_CHAR + r'\b'
PATTERN = b'\\b(?:' + HEX_DIGIT + IGNORED + b'){7,}' + HEX_DIGIT + b'\\b'

# at least 4 hex chars, followed by whitespace or CR/LF: (?:[0-9A-Fa-f]{2}){4,}\s*
# PATTERN = r'(?:(?:[0-9A-Fa-f]{2})+\s*)*(?:[0-9A-Fa-f]{2}){4,}'
# improved pattern, allowing semicolons within hex:
#PATTERN = r'(?:(?:[0-9A-Fa-f]{2})+\s*)*(?:[0-9A-Fa-f]{2}){4,}'

re_hexblock = re.compile(PATTERN)
re_embedded_tags = re.compile(IGNORED)
re_decimal = re.compile(b'\\d+')

re_delimiter = re.compile(b'[ \\t\\r\\n\\f\\v]')

DELIMITER = b'[ \\t\\r\\n\\f\\v]'
DELIMITERS_ZeroOrMore = b'[ \\t\\r\\n\\f\\v]*'
BACKSLASH_BIN = b'\\\\bin'
# According to my tests, Word accepts up to 250 digits (leading zeroes)
DECIMAL_GROUP = b'(\d{1,250})'

re_delims_bin_decimal = re.compile(DELIMITERS_ZeroOrMore + BACKSLASH_BIN
                                   + DECIMAL_GROUP + DELIMITER)
re_delim_hexblock = re.compile(DELIMITER + PATTERN)

# TODO: use a frozenset instead of a regex?
re_executable_extensions = re.compile(
    r"(?i)\.(BAT|CLASS|CMD|CPL|DLL|EXECOM|GADGET|HTA|INF|JAR|JS|JSE|LNK|MSC|MSI|MSP|PIF|PS1|PS1XML|PS2|PS2XML|PSC1|PSC2|REG|SCF|SCR|SCT|VB|VBE|VBS|WS|WSC|WSF|WSH)\b")

# Destination Control Words, according to MS RTF Specifications v1.9.1:
DESTINATION_CONTROL_WORDS = frozenset((
    b"aftncn", b"aftnsep", b"aftnsepc", b"annotation", b"atnauthor", b"atndate", b"atnid", b"atnparent", b"atnref",
    b"atrfend", b"atrfstart", b"author", b"background", b"bkmkend", b"bkmkstart", b"blipuid", b"buptim", b"category",
    b"colorschememapping", b"colortbl", b"comment", b"company", b"creatim", b"datafield", b"datastore", b"defchp", b"defpap",
    b"do", b"doccomm", b"docvar", b"dptxbxtext", b"ebcend", b"ebcstart", b"factoidname", b"falt", b"fchars", b"ffdeftext",
    b"ffentrymcr", b"ffexitmcr", b"ffformat", b"ffhelptext", b"ffl", b"ffname",b"ffstattext", b"field", b"file", b"filetbl",
    b"fldinst", b"fldrslt", b"fldtype", b"fontemb", b"fonttbl", b"footer", b"footerf", b"footerl",
    b"footerr", b"footnote", b"formfield", b"ftncn", b"ftnsep", b"ftnsepc", b"g", b"generator", b"gridtbl", b"header", b"headerf",
    b"headerl", b"headerr", b"hl", b"hlfr", b"hlinkbase", b"hlloc", b"hlsrc", b"hsv", b"info", b"keywords",
    b"latentstyles", b"lchars", b"levelnumbers", b"leveltext", b"lfolevel", b"linkval", b"list", b"listlevel", b"listname",
    b"listoverride", b"listoverridetable", b"listpicture", b"liststylename", b"listtable", b"listtext", b"lsdlockedexcept",
    b"macc", b"maccPr", b"mailmerge", b"malnScr", b"manager", b"margPr", b"mbar", b"mbarPr", b"mbaseJc", b"mbegChr",
    b"mborderBox", b"mborderBoxPr", b"mbox", b"mboxPr", b"mchr", b"mcount", b"mctrlPr", b"md", b"mdeg", b"mdegHide", b"mden",
    b"mdiff", b"mdPr", b"me", b"mendChr", b"meqArr", b"meqArrPr", b"mf", b"mfName", b"mfPr", b"mfunc", b"mfuncPr",b"mgroupChr",
    b"mgroupChrPr",b"mgrow", b"mhideBot", b"mhideLeft", b"mhideRight", b"mhideTop", b"mlim", b"mlimLoc", b"mlimLow",
    b"mlimLowPr", b"mlimUpp", b"mlimUppPr", b"mm", b"mmaddfieldname", b"mmathPict", b"mmaxDist", b"mmc",
    b"mmcJc", b"mmconnectstr", b"mmconnectstrdata", b"mmcPr", b"mmcs", b"mmdatasource", b"mmheadersource", b"mmmailsubject",
    b"mmodso", b"mmodsofilter", b"mmodsofldmpdata", b"mmodsomappedname", b"mmodsoname", b"mmodsorecipdata", b"mmodsosort",
    b"mmodsosrc", b"mmodsotable", b"mmodsoudl", b"mmodsoudldata", b"mmodsouniquetag", b"mmPr", b"mmquery", b"mmr", b"mnary",
    b"mnaryPr", b"mnoBreak", b"mnum", b"mobjDist", b"moMath", b"moMathPara", b"moMathParaPr", b"mopEmu", b"mphant", b"mphantPr",
    b"mplcHide", b"mpos", b"mr", b"mrad", b"mradPr", b"mrPr", b"msepChr", b"mshow", b"mshp", b"msPre", b"msPrePr", b"msSub",
    b"msSubPr", b"msSubSup", b"msSubSupPr",  b"msSup", b"msSupPr", b"mstrikeBLTR", b"mstrikeH", b"mstrikeTLBR", b"mstrikeV",
    b"msub", b"msubHide", b"msup", b"msupHide", b"mtransp", b"mtype", b"mvertJc", b"mvfmf", b"mvfml", b"mvtof", b"mvtol",
    b"mzeroAsc", b"mzeroDesc", b"mzeroWid", b"nesttableprops", b"nonesttables", b"objalias", b"objclass",
    b"objdata", b"object", b"objname", b"objsect", b"oldcprops", b"oldpprops", b"oldsprops", b"oldtprops",
    b"oleclsid", b"operator", b"panose", b"password", b"passwordhash", b"pgp", b"pgptbl", b"picprop", b"pict", b"pn", b"pnseclvl",
    b"pntext", b"pntxta", b"pntxtb", b"printim",
    b"propname", b"protend", b"protstart", b"protusertbl",
    b"result", b"revtbl", b"revtim",
    # \rtf should not be treated as a destination (issue #522)
    #b"rtf",
    b"rxe", b"shp", b"shpgrp", b"shpinst", b"shppict", b"shprslt", b"shptxt",
    b"sn", b"sp", b"staticval", b"stylesheet", b"subject", b"sv", b"svb", b"tc", b"template", b"themedata", b"title", b"txe", b"ud",
    b"upr", b"userprops", b"wgrffmtfilter", b"windowcaption", b"writereservation", b"writereservhash", b"xe", b"xform",
    b"xmlattrname", b"xmlattrvalue", b"xmlclose", b"xmlname", b"xmlnstbl", b"xmlopen",
    # added for issue #292: https://github.com/decalage2/oletools/issues/292
    b"margSz",
    # added for issue #327:
    b"pnaiu", b"pnaiud",

    # It seems \private should not be treated as a destination (issue #178)
    # Same for \pxe (issue #196)
    # b"private", b"pxe",
    # from issue #303: These destination control words can be treated as a "value" type.
    # They don't consume data so they won't change the state of the parser.
    # b"atnicn", b"atntime", b"fname", b"fontfile", b"htmltag", b"keycode", b"maln",
    # b"mhtmltag", b"mmath", b"mmathPr", b"nextfile", b"objtime", b"rsidtbl",
    ))


# some str methods on Python 2.x return characters,
# while the equivalent bytes methods return integers on Python 3.x:
if sys.version_info[0] <= 2:
    # Python 2.x - Characters (str)
    BACKSLASH = '\\'
    BRACE_OPEN = '{'
    BRACE_CLOSE = '}'
    UNICODE_TYPE = unicode
else:
    # Python 3.x - Integers
    BACKSLASH = ord('\\')
    BRACE_OPEN = ord('{')
    BRACE_CLOSE = ord('}')
    UNICODE_TYPE = str

RTF_MAGIC = b'\x7b\\rt'   # \x7b == b'{' but does not mess up auto-indent


#=== CLASSES =================================================================

class Destination(object):
    """
    Stores the data associated with a destination control word
    """
    def __init__(self, cword=None):
        self.cword = cword
        self.data = b''
        self.start = None
        self.end = None
        self.group_level = 0


class RtfParser(object):
    """
    Very simple but robust generic RTF parser, designed to handle
    malformed malicious RTF as MS Word does
    """

    def __init__(self, data):
        """
        RtfParser constructor.
        
        :param data: bytes object containing the RTF data to be parsed 
        """
        self.data = data
        self.index = 0
        self.size = len(data)
        self.group_level = 0
        # default destination for the document text:
        document_destination = Destination()
        self.destinations = [document_destination]
        self.current_destination = document_destination

    def parse(self):
        """
        Parse the RTF data
        
        :return: nothing
        """
        # Start at beginning of data
        self.index = 0
        start_time = time()
        last_report = start_time
        # Loop until the end
        while self.index < self.size:
            if time() - last_report > 15:     # report every 15s
                last_report = time()
            if self.data[self.index] == BRACE_OPEN:
                # Found an opening brace "{": Start of a group
                self._open_group()
                self.index += 1
                continue
            if self.data[self.index] == BRACE_CLOSE:
                # Found a closing brace "}": End of a group
                self._close_group()
                self.index += 1
                continue
            if self.data[self.index] == BACKSLASH:
                # Found a backslash "\": Start of a control word or control symbol
                # Use a regex to extract the control word name if present:
                # NOTE: the full length of the control word + its optional integer parameter
                # is limited by MS Word at 253 characters, so we have to run the regex
                # on a cropped string:
                data_cropped = self.data[self.index:self.index+254]
                # append a space so that the regex can check the following character:
                data_cropped += b' '
                # m = re_control_word.match(self.data, self.index, self.index+253)
                m = re_control_word.match(data_cropped)
                if m:
                    cword = m.group(1)
                    param = None
                    if len(m.groups()) > 1:
                        param = m.group(2)
                    # log.debug('control word at index %Xh - cword=%r param=%r  %r' % (self.index, cword, param, m.group()))
                    self._control_word(m, cword, param)
                    self.index += len(m.group())
                    # if it's \bin, call _bin after updating index
                    if cword == b'bin':
                        self._bin(m, param)
                    continue
                # Otherwise, it may be a control symbol:
                m = re_control_symbol.match(self.data, self.index)
                if m:
                    self.control_symbol(m)
                    self.index += len(m.group())
                    continue
            # Otherwise, this is plain text:
            # Use a regex to match all characters until the next brace or backslash:
            m = re_text.match(self.data, self.index)
            if m:
                self._text(m)
                self.index += len(m.group())
                continue
            raise RuntimeError('Should not have reached this point - index=%Xh' % self.index)
        # call _end_of_file to make sure all groups are closed properly
        self._end_of_file()


    def _open_group(self):
        self.group_level += 1
        #log.debug('{ Open Group at index %Xh - level=%d' % (self.index, self.group_level))
        # call user method AFTER increasing the level:
        self.open_group()

    def open_group(self):
        #log.debug('open group at index %Xh' % self.index)
        pass

    def _close_group(self):
        #log.debug('} Close Group at index %Xh - level=%d' % (self.index, self.group_level))
        # call user method BEFORE decreasing the level:
        self.close_group()
        # if the destination level is the same as the group level, close the destination:
        if self.group_level == self.current_destination.group_level:
            # log.debug('Current Destination %r level = %d => Close Destination' % (
            #     self.current_destination.cword, self.current_destination.group_level))
            self._close_destination()
        else:
            # log.debug('Current Destination %r level = %d => Continue with same Destination' % (
            #     self.current_destination.cword, self.current_destination.group_level))
            pass
        self.group_level -= 1
        # log.debug('Decreased group level to %d' % self.group_level)

    def close_group(self):
        #log.debug('close group at index %Xh' % self.index)
        pass

    def _open_destination(self, matchobject, cword):
        # if the current destination is at the same group level, close it first:
        if self.current_destination.group_level == self.group_level:
            self._close_destination()
        new_dest = Destination(cword)
        new_dest.group_level = self.group_level
        self.destinations.append(new_dest)
        self.current_destination = new_dest
        # start of the destination is right after the control word:
        new_dest.start = self.index + len(matchobject.group())
        # log.debug("Open Destination %r start=%Xh - level=%d" % (cword, new_dest.start, new_dest.group_level))
        # call the corresponding user method for additional processing:
        self.open_destination(self.current_destination)

    def open_destination(self, destination):
        pass

    def _close_destination(self):
        # log.debug("Close Destination %r end=%Xh - level=%d" % (self.current_destination.cword,
        #     self.index, self.current_destination.group_level))
        self.current_destination.end = self.index
        # call the corresponding user method for additional processing:
        self.close_destination(self.current_destination)
        if len(self.destinations)>0:
            # remove the current destination from the stack, and go back to the previous one:
            self.destinations.pop()
        if len(self.destinations) > 0:
            self.current_destination = self.destinations[-1]
        else:
            # log.debug('All destinations are closed, keeping the document destination open')
            pass

    def close_destination(self, destination):
        pass

    def _control_word(self, matchobject, cword, param):
        #log.debug('control word %r at index %Xh' % (matchobject.group(), self.index))
        # TODO: according to RTF specs v1.9.1, "Destination changes are legal only immediately after an opening brace ({)"
        # (not counting the special control symbol \*, of course)
        if cword in DESTINATION_CONTROL_WORDS:
            log.debug('%r is a destination control word: starting a new destination at index %Xh' % (cword, self.index))
            self._open_destination(matchobject, cword)
        # call the corresponding user method for additional processing:
        self.control_word(matchobject, cword, param)

    def control_word(self, matchobject, cword, param):
        pass

    def control_symbol(self, matchobject):
        #log.debug('control symbol %r at index %Xh' % (matchobject.group(), self.index))
        pass

    def _text(self, matchobject):
        text = matchobject.group()
        self.current_destination.data += text
        self.text(matchobject, text)

    def text(self, matchobject, text):
        #log.debug('text %r at index %Xh' % (matchobject.group(), self.index))
        pass

    def _bin(self, matchobject, param):
        if param is None:
            log.info('Detected anti-analysis trick: \\bin object without length at index %X' % self.index)
            binlen = 0
        else:
            binlen = int(param)
        # handle negative length
        if binlen < 0:
            log.info('Detected anti-analysis trick: \\bin object with negative length at index %X' % self.index)
            # binlen = int(param.strip('-'))
            # According to my tests, if the bin length is negative,
            # it should be treated as a null length:
            binlen=0
        # ignore optional space after \bin
        if ord(self.data[self.index:self.index + 1]) == ord(' '):
            log.debug('\\bin: ignoring whitespace before data')
            self.index += 1
        log.debug('\\bin: reading %d bytes of binary data' % binlen)
        # TODO: handle length greater than data
        bindata = self.data[self.index:self.index + binlen]
        self.index += binlen
        self.bin(bindata)

    def bin(self, bindata):
        pass

    def _end_of_file(self):
        # log.debug('%Xh Reached End of File')
        # close any group/destination that is still open:
        while self.group_level > 0:
            log.debug('Group Level = %d, closing group' % self.group_level)
            self._close_group()
        self.end_of_file()

    def end_of_file(self):
        pass


class RtfObject(object):
    """
    An object or a file (OLE Package) embedded into an RTF document
    """
    def __init__(self):
        """
        RtfObject constructor
        """
        # start and end index in the RTF file:
        self.start = None
        self.end = None
        # raw object data encoded in hexadecimal, as found in the RTF file:
        self.hexdata = None
        # raw object data in binary form, decoded from hexadecimal
        self.rawdata = None
        # OLE object data (extracted from rawdata)
        self.is_ole = False
        self.oledata = None
        self.format_id = None
        self.class_name = None
        self.oledata_size = None
        # OLE Package data (extracted from oledata)
        self.is_package = False
        self.olepkgdata = None
        self.filename = None
        self.src_path = None
        self.temp_path = None
        # Additional OLE object data
        self.clsid = None
        self.clsid_desc = None




class RtfObjParser(RtfParser):
    """
    Specialized RTF parser to extract OLE objects
    """

    def __init__(self, data):
        super(RtfObjParser, self).__init__(data)
        # list of RtfObjects found
        self.objects = []

    def open_destination(self, destination):
        # TODO: detect when the destination is within an objdata, report as obfuscation
        if destination.cword == b'objdata':
            log.debug('*** Start object data at index %Xh' % destination.start)

    def close_destination(self, destination):
        if destination.cword == b'objdata':
            log.debug('*** Close object data at index %Xh' % self.index)
            rtfobj = RtfObject()
            self.objects.append(rtfobj)
            rtfobj.start = destination.start
            rtfobj.end = destination.end
            # Filter out all whitespaces first (just ignored):
            hexdata1 = destination.data.translate(None, b' \t\r\n\f\v')
            # Then filter out any other non-hex character:
            hexdata = re.sub(b'[^a-fA-F0-9]', b'', hexdata1)
            if len(hexdata) < len(hexdata1):
                # this is only for debugging:
                nonhex = re.sub(b'[a-fA-F0-9]', b'', hexdata1)
                log.debug('Found non-hex chars in hexdata: %r' % nonhex)
            # MS Word accepts an extra hex digit, so we need to trim it if present:
            if len(hexdata) & 1:
                log.debug('Odd length, trimmed last byte.')
                hexdata = hexdata[:-1]
            rtfobj.hexdata = hexdata
            object_data = binascii.unhexlify(hexdata)
            rtfobj.rawdata = object_data
            rtfobj.rawdata_md5 = hashlib.md5(object_data).hexdigest()                    
            # TODO: check if all hex data is extracted properly

            obj = oleobj.OleObject()
            try:
                obj.parse(object_data)
                rtfobj.format_id = obj.format_id
                rtfobj.class_name = obj.class_name
                rtfobj.oledata_size = obj.data_size
                rtfobj.oledata = obj.data
                rtfobj.oledata_md5 = hashlib.md5(obj.data).hexdigest()         
                rtfobj.is_ole = True
                if obj.class_name.lower() == b'package':
                    opkg = oleobj.OleNativeStream(bindata=obj.data,
                                                  package=True)
                    rtfobj.filename = opkg.filename
                    rtfobj.src_path = opkg.src_path
                    rtfobj.temp_path = opkg.temp_path
                    rtfobj.olepkgdata = opkg.data
                    rtfobj.olepkgdata_md5 = hashlib.md5(opkg.data).hexdigest()     
                    rtfobj.is_package = True
                else:
                    if olefile.isOleFile(obj.data):
                        ole = olefile.OleFileIO(obj.data)
                        rtfobj.clsid = ole.root.clsid
                        rtfobj.clsid_desc = clsid.KNOWN_CLSIDS.get(rtfobj.clsid,
                            'unknown CLSID (please report at https://github.com/decalage2/oletools/issues)')
            except:
                pass
                log.debug('*** Not an OLE 1.0 Object')

    def bin(self, bindata):
        if self.current_destination.cword == b'objdata':
            # TODO: keep track of this, because it is unusual and indicates potential obfuscation
            # trick: hexlify binary data, add it to hex data
            self.current_destination.data += binascii.hexlify(bindata)

    def control_word(self, matchobject, cword, param):
        # TODO: extract useful cwords such as objclass
        # TODO: keep track of cwords inside objdata, because it is unusual and indicates potential obfuscation
        # TODO: same with control symbols, and opening bracket
        # log.debug('- Control word "%s", param=%s, level=%d' % (cword, param, self.group_level))
        pass

    def control_symbol(self, matchobject):
        # log.debug('control symbol %r at index %Xh' % (matchobject.group(), self.index))
        symbol = matchobject.group()[1:2]
        if symbol == b"'":
            # read the two hex digits following "\'" - which can be any characters, not just hex digits
            # (because within an objdata destination, they are simply ignored)
            hexdigits = self.data[self.index+2:self.index+4]
            # print(hexdigits)
            # move the index two bytes forward
            self.index += 2
            if self.current_destination.cword == b'objdata':
                # Here's the tricky part: there is a bug in the MS Word RTF parser at least
                # until Word 2016, that removes the last hex digit before the \'hh control
                # symbol, ONLY IF the number of hex digits read so far is odd.
                # So to emulate that bug, we have to clean the data read so far by keeping
                # only the hex digits:
                # Filter out any non-hex character:
                self.current_destination.data = re.sub(b'[^a-fA-F0-9]', b'', self.current_destination.data)
                if len(self.current_destination.data) & 1 == 1:
                    # If the number of hex digits is odd, remove the last one:
                    self.current_destination.data = self.current_destination.data[:-1]


#=== FUNCTIONS ===============================================================
def process(data):
    rtfp = RtfObjParser(data)
    rtfp.parse()
    results = list()
    for rtfobj in rtfp.objects:
        r = dict()
        if rtfobj.is_ole:
            r['is_ole'] = True
            r['format_id'] = rtfobj.format_id
            if rtfobj.format_id == oleobj.OleObject.TYPE_EMBEDDED:
                r['format_type'] = 'Embedded'
            elif rtfobj.format_id == oleobj.OleObject.TYPE_LINKED:
                r['format_type'] = 'Linked'
            else:
                r['format_type'] = 'Unknown'
            r['class_name'] = rtfobj.class_name
            if r['class_name']:
                r['class_name'] = r['class_name'].decode('utf8', 'ignore')
            # if the object is linked and not embedded, data_size=None:
            if rtfobj.oledata_size is None:
                r['data_size'] = -1
            else:
                r['data_size'] = rtfobj.oledata_size
            if rtfobj.is_package:
                r['is_package'] = True
                r['file_name'] = rtfobj.filename
                r['src_path'] = rtfobj.src_path
                r['temp_path'] = rtfobj.temp_path
                r['md5'] = rtfobj.olepkgdata_md5
            else:
                r['md5'] = rtfobj.oledata_md5
            if rtfobj.clsid is not None:
                r['clsid'] = rtfobj.clsid
                r['clsid_desc'] = rtfobj.clsid_desc
            # Detect OLE2Link exploit
            # http://www.kb.cert.org/vuls/id/921560
            if rtfobj.class_name == b'OLE2Link':
                found_list =  re.findall(r'[a-fA-F0-9\x0D\x0A]{128,}',data)
                urls = []
                for item in found_list:
                    try:
                        temp = item.replace("\x0D\x0A","").decode("hex")
                    except:
                        continue
                    pat = re.compile(r'(?:[\x20-\x7E][\x00]){3,}')
                    words = [w.decode('utf-16le') for w in pat.findall(temp)]
                    for w in words:
                        if "http" in w:
                            urls.append(w)
                urls = sorted(set(urls))
                if urls:
                    r['urls'] = urls
            results.append(r)

    return results
