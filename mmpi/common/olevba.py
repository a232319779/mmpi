# -*- coding: utf-8 -*-
# @Time    : 2020/12/21 23:02:27
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : olevba.py
# @Software: Visual Studio Code


import struct
import math
import logging
import olefile
from io import BytesIO

from mmpi.common import codepages

MODULE_EXTENSION = "bas"
CLASS_EXTENSION = "cls"
FORM_EXTENSION = "frm"

# === LOGGING =================================================================


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
    logger.addHandler(logging.NullHandler())
    logger.setLevel(level)
    return logger


# a global logger object used for debugging:
log = get_logger('olevba')


class OlevbaBaseException(Exception):
    """ Base class for exceptions produced here for simpler except clauses """

    def __init__(self, msg, filename=None, orig_exc=None, **kwargs):
        if orig_exc:
            super(OlevbaBaseException, self).__init__(msg +
                                                      ' ({0})'.format(
                                                          orig_exc),
                                                      **kwargs)
        else:
            super(OlevbaBaseException, self).__init__(msg, **kwargs)
        self.msg = msg
        self.filename = filename
        self.orig_exc = orig_exc


class FileOpenError(OlevbaBaseException):
    """ raised by VBA_Parser constructor if all open_... attempts failed

    probably means the file type is not supported
    """

    def __init__(self, filename, orig_exc=None):
        super(FileOpenError, self).__init__(
            'Failed to open file %s' % filename, filename, orig_exc)


class ProcessingError(OlevbaBaseException):
    """ raised by VBA_Parser.process_file* functions """

    def __init__(self, filename, orig_exc):
        super(ProcessingError, self).__init__(
            'Error processing file %s' % filename, filename, orig_exc)


class MsoExtractionError(RuntimeError, OlevbaBaseException):
    """ raised by mso_file_extract if parsing MSO/ActiveMIME data failed """

    def __init__(self, msg):
        MsoExtractionError.__init__(self, msg)
        OlevbaBaseException.__init__(self, msg)


class SubstreamOpenError(FileOpenError):
    """ special kind of FileOpenError: file is a substream of original file """

    def __init__(self, filename, subfilename, orig_exc=None):
        super(SubstreamOpenError, self).__init__(
            str(filename) + '/' + str(subfilename), orig_exc)
        self.filename = filename   # overwrite setting in OlevbaBaseException
        self.subfilename = subfilename


class UnexpectedDataError(OlevbaBaseException):
    """ raised when parsing is strict (=not relaxed) and data is unexpected """

    def __init__(self, stream_path, variable, expected, value):
        if isinstance(expected, int):
            es = '{0:04X}'.format(expected)
        elif isinstance(expected, tuple):
            es = ','.join('{0:04X}'.format(e) for e in expected)
            es = '({0})'.format(es)
        else:
            raise ValueError(
                'Unknown type encountered: {0}'.format(type(expected)))
        super(UnexpectedDataError, self).__init__(
            'Unexpected value in {0} for variable {1}: '
            'expected {2} but found {3:04X}!'
            .format(stream_path, variable, es, value))
        self.stream_path = stream_path
        self.variable = variable
        self.expected = expected
        self.value = value


def copytoken_help(decompressed_current, decompressed_chunk_start):
    """
    compute bit masks to decode a CopyToken according to MS-OVBA 2.4.1.3.19.1 CopyToken Help

    decompressed_current: number of decompressed bytes so far, i.e. len(decompressed_container)
    decompressed_chunk_start: offset of the current chunk in the decompressed container
    return length_mask, offset_mask, bit_count, maximum_length
    """
    difference = decompressed_current - decompressed_chunk_start
    bit_count = int(math.ceil(math.log(difference, 2)))
    bit_count = max([bit_count, 4])
    length_mask = 0xFFFF >> bit_count
    offset_mask = ~length_mask
    maximum_length = (0xFFFF >> bit_count) + 3
    return length_mask, offset_mask, bit_count, maximum_length


def decompress_stream(compressed_container):
    """
    Decompress a stream according to MS-OVBA section 2.4.1

    :param compressed_container bytearray: bytearray or bytes compressed according to the MS-OVBA 2.4.1.3.6 Compression algorithm
    :return: the decompressed container as a bytes string
    :rtype: bytes
    """
    # 2.4.1.2 State Variables

    # The following state is maintained for the CompressedContainer (section 2.4.1.1.1):
    # CompressedRecordEnd: The location of the byte after the last byte in the CompressedContainer (section 2.4.1.1.1).
    # CompressedCurrent: The location of the next byte in the CompressedContainer (section 2.4.1.1.1) to be read by
    #                    decompression or to be written by compression.

    # The following state is maintained for the current CompressedChunk (section 2.4.1.1.4):
    # CompressedChunkStart: The location of the first byte of the CompressedChunk (section 2.4.1.1.4) within the
    #                       CompressedContainer (section 2.4.1.1.1).

    # The following state is maintained for a DecompressedBuffer (section 2.4.1.1.2):
    # DecompressedCurrent: The location of the next byte in the DecompressedBuffer (section 2.4.1.1.2) to be written by
    #                      decompression or to be read by compression.
    # DecompressedBufferEnd: The location of the byte after the last byte in the DecompressedBuffer (section 2.4.1.1.2).

    # The following state is maintained for the current DecompressedChunk (section 2.4.1.1.3):
    # DecompressedChunkStart: The location of the first byte of the DecompressedChunk (section 2.4.1.1.3) within the
    #                         DecompressedBuffer (section 2.4.1.1.2).

    # Check the input is a bytearray, otherwise convert it (assuming it's bytes):
    if not isinstance(compressed_container, bytearray):
        compressed_container = bytearray(compressed_container)
        # raise TypeError('decompress_stream requires a bytearray as input')
    decompressed_container = bytearray()  # result
    compressed_current = 0

    sig_byte = compressed_container[compressed_current]
    if sig_byte != 0x01:
        raise ValueError('invalid signature byte {0:02X}'.format(sig_byte))

    compressed_current += 1

    # NOTE: the definition of CompressedRecordEnd is ambiguous. Here we assume that
    # CompressedRecordEnd = len(compressed_container)
    while compressed_current < len(compressed_container):
        # 2.4.1.1.5
        compressed_chunk_start = compressed_current
        # chunk header = first 16 bits
        compressed_chunk_header = \
            struct.unpack(
                "<H", compressed_container[compressed_chunk_start:compressed_chunk_start + 2])[0]
        # chunk size = 12 first bits of header + 3
        chunk_size = (compressed_chunk_header & 0x0FFF) + 3
        # chunk signature = 3 next bits - should always be 0b011
        chunk_signature = (compressed_chunk_header >> 12) & 0x07
        if chunk_signature != 0b011:
            raise ValueError(
                'Invalid CompressedChunkSignature in VBA compressed stream')
        # chunk flag = next bit - 1 == compressed, 0 == uncompressed
        chunk_flag = (compressed_chunk_header >> 15) & 0x01
        log.debug("chunk size = {0}, compressed flag = {1}".format(
            chunk_size, chunk_flag))

        # MS-OVBA 2.4.1.3.12: the maximum size of a chunk including its header is 4098 bytes (header 2 + data 4096)
        # The minimum size is 3 bytes
        # NOTE: there seems to be a typo in MS-OVBA, the check should be with 4098, not 4095 (which is the max value
        # in chunk header before adding 3.
        # Also the first test is not useful since a 12 bits value cannot be larger than 4095.
        if chunk_flag == 1 and chunk_size > 4098:
            raise ValueError(
                'CompressedChunkSize > 4098 but CompressedChunkFlag == 1')
        if chunk_flag == 0 and chunk_size != 4098:
            raise ValueError(
                'CompressedChunkSize != 4098 but CompressedChunkFlag == 0')

        # check if chunk_size goes beyond the compressed data, instead of silently cutting it:
        # TODO: raise an exception?
        if compressed_chunk_start + chunk_size > len(compressed_container):
            log.warning('Chunk size is larger than remaining compressed data')
        compressed_end = min(
            [len(compressed_container), compressed_chunk_start + chunk_size])
        # read after chunk header:
        compressed_current = compressed_chunk_start + 2

        if chunk_flag == 0:
            # MS-OVBA 2.4.1.3.3 Decompressing a RawChunk
            # uncompressed chunk: read the next 4096 bytes as-is
            # TODO: check if there are at least 4096 bytes left
            decompressed_container.extend(
                compressed_container[compressed_current:compressed_current + 4096])
            compressed_current += 4096
        else:
            # MS-OVBA 2.4.1.3.2 Decompressing a CompressedChunk
            # compressed chunk
            decompressed_chunk_start = len(decompressed_container)
            while compressed_current < compressed_end:
                # MS-OVBA 2.4.1.3.4 Decompressing a TokenSequence
                # log.debug('compressed_current = %d / compressed_end = %d' % (compressed_current, compressed_end))
                # FlagByte: 8 bits indicating if the following 8 tokens are either literal (1 byte of plain text) or
                # copy tokens (reference to a previous literal token)
                flag_byte = compressed_container[compressed_current]
                compressed_current += 1
                for bit_index in range(0, 8):
                    # log.debug('bit_index=%d / compressed_current=%d / compressed_end=%d' % (bit_index, compressed_current, compressed_end))
                    if compressed_current >= compressed_end:
                        break
                    # MS-OVBA 2.4.1.3.5 Decompressing a Token
                    # MS-OVBA 2.4.1.3.17 Extract FlagBit
                    flag_bit = (flag_byte >> bit_index) & 1
                    # log.debug('bit_index=%d: flag_bit=%d' % (bit_index, flag_bit))
                    if flag_bit == 0:  # LiteralToken
                        # copy one byte directly to output
                        decompressed_container.extend(
                            [compressed_container[compressed_current]])
                        compressed_current += 1
                    else:  # CopyToken
                        # MS-OVBA 2.4.1.3.19.2 Unpack CopyToken
                        copy_token = \
                            struct.unpack(
                                "<H", compressed_container[compressed_current:compressed_current + 2])[0]
                        # TODO: check this
                        length_mask, offset_mask, bit_count, _ = copytoken_help(
                            len(decompressed_container), decompressed_chunk_start)
                        length = (copy_token & length_mask) + 3
                        temp1 = copy_token & offset_mask
                        temp2 = 16 - bit_count
                        offset = (temp1 >> temp2) + 1
                        # log.debug('offset=%d length=%d' % (offset, length))
                        copy_source = len(decompressed_container) - offset
                        for index in range(copy_source, copy_source + length):
                            decompressed_container.extend(
                                [decompressed_container[index]])
                        compressed_current += 2
    return bytes(decompressed_container)


class VBA_Module(object):
    """
    Class to parse a VBA module from an OLE file, and to store all the corresponding
    metadata and VBA source code.
    """

    def __init__(self, project, dir_stream, module_index):
        """
        Parse a VBA Module record from the dir stream of a VBA project.
        Reference: MS-OVBA 2.3.4.2.3.2 MODULE Record

        :param VBA_Project project: VBA_Project, corresponding VBA project
        :param olefile.OleStream dir_stream: olefile.OleStream, file object containing the module record
        :param int module_index: int, index of the module in the VBA project list
        """
        #: reference to the VBA project for later use (VBA_Project)
        self.project = project
        #: VBA module name (unicode str)
        self.name = None
        #: VBA module name as a native str (utf8 bytes on py2, str on py3)
        self.name_str = None
        #: VBA module name, unicode copy (unicode str)
        self._name_unicode = None
        #: Stream name containing the VBA module (unicode str)
        self.streamname = None
        #: Stream name containing the VBA module as a native str (utf8 bytes on py2, str on py3)
        self.streamname_str = None
        self._streamname_unicode = None
        self.docstring = None
        self._docstring_unicode = None
        self.textoffset = None
        self.type = None
        self.readonly = False
        self.private = False
        #: VBA source code in bytes format, using the original code page from the VBA project
        self.code_raw = None
        #: VBA source code in unicode format (unicode for Python2, str for Python 3)
        self.code = None
        #: VBA source code in native str format (str encoded with UTF-8 for Python 2, str for Python 3)
        self.code_str = None
        #: VBA module file name including an extension based on the module type such as bas, cls, frm (unicode str)
        self.filename = None
        #: VBA module file name in native str format (str)
        self.filename_str = None
        self.code_path = None
        try:
            # 2.3.4.2.3.2.1 MODULENAME Record
            # Specifies a VBA identifier as the name of the containing MODULE Record
            _id = struct.unpack("<H", dir_stream.read(2))[0]
            project.check_value('MODULENAME_Id', 0x0019, _id)
            size = struct.unpack("<L", dir_stream.read(4))[0]
            modulename_bytes = dir_stream.read(size)
            # Module name always stored as Unicode:
            self.name = project.decode_bytes(modulename_bytes)
            self.name_str = self.name
            # account for optional sections
            # TODO: shouldn't this be a loop? (check MS-OVBA)
            section_id = struct.unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x0047:
                # 2.3.4.2.3.2.2 MODULENAMEUNICODE Record
                # Specifies a VBA identifier as the name of the containing MODULE Record (section 2.3.4.2.3.2).
                # MUST contain the UTF-16 encoding of MODULENAME Record
                size = struct.unpack("<L", dir_stream.read(4))[0]
                self._name_unicode = dir_stream.read(
                    size).decode('UTF-16LE', 'replace')
                section_id = struct.unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x001A:
                # 2.3.4.2.3.2.3 MODULESTREAMNAME Record
                # Specifies the stream name of the ModuleStream (section 2.3.4.3) in the VBA Storage (section 2.3.4)
                # corresponding to the containing MODULE Record
                size = struct.unpack("<L", dir_stream.read(4))[0]
                streamname_bytes = dir_stream.read(size)
                # Store it as Unicode:
                self.streamname = project.decode_bytes(streamname_bytes)
                self.streamname_str = self.streamname
                reserved = struct.unpack("<H", dir_stream.read(2))[0]
                project.check_value(
                    'MODULESTREAMNAME_Reserved', 0x0032, reserved)
                size = struct.unpack("<L", dir_stream.read(4))[0]
                self._streamname_unicode = dir_stream.read(
                    size).decode('UTF-16LE', 'replace')
                section_id = struct.unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x001C:
                # 2.3.4.2.3.2.4 MODULEDOCSTRING Record
                # Specifies the description for the containing MODULE Record
                size = struct.unpack("<L", dir_stream.read(4))[0]
                docstring_bytes = dir_stream.read(size)
                self.docstring = project.decode_bytes(docstring_bytes)
                reserved = struct.unpack("<H", dir_stream.read(2))[0]
                project.check_value(
                    'MODULEDOCSTRING_Reserved', 0x0048, reserved)
                size = struct.unpack("<L", dir_stream.read(4))[0]
                self._docstring_unicode = dir_stream.read(size)
                section_id = struct.unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x0031:
                # 2.3.4.2.3.2.5 MODULEOFFSET Record
                # Specifies the location of the source code within the ModuleStream (section 2.3.4.3)
                # that corresponds to the containing MODULE Record
                size = struct.unpack("<L", dir_stream.read(4))[0]
                project.check_value('MODULEOFFSET_Size', 0x0004, size)
                self.textoffset = struct.unpack("<L", dir_stream.read(4))[0]
                section_id = struct.unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x001E:
                # 2.3.4.2.3.2.6 MODULEHELPCONTEXT Record
                # Specifies the Help topic identifier for the containing MODULE Record
                modulehelpcontext_size = struct.unpack(
                    "<L", dir_stream.read(4))[0]
                project.check_value('MODULEHELPCONTEXT_Size',
                                    0x0004, modulehelpcontext_size)
                # HelpContext (4 bytes): An unsigned integer that specifies the Help topic identifier
                # in the Help file specified by PROJECTHELPFILEPATH Record
                helpcontext = struct.unpack("<L", dir_stream.read(4))[0]
                section_id = struct.unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x002C:
                # 2.3.4.2.3.2.7 MODULECOOKIE Record
                # Specifies ignored data.
                size = struct.unpack("<L", dir_stream.read(4))[0]
                project.check_value('MODULECOOKIE_Size', 0x0002, size)
                cookie = struct.unpack("<H", dir_stream.read(2))[0]
                section_id = struct.unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x0021 or section_id == 0x0022:
                # 2.3.4.2.3.2.8 MODULETYPE Record
                # Specifies whether the containing MODULE Record (section 2.3.4.2.3.2) is a procedural module,
                # document module, class module, or designer module.
                # Id (2 bytes): An unsigned integer that specifies the identifier for this record.
                # MUST be 0x0021 when the containing MODULE Record (section 2.3.4.2.3.2) is a procedural module.
                # MUST be 0x0022 when the containing MODULE Record (section 2.3.4.2.3.2) is a document module,
                # class module, or designer module.
                self.type = section_id
                reserved = struct.unpack("<L", dir_stream.read(4))[0]
                section_id = struct.unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x0025:
                # 2.3.4.2.3.2.9 MODULEREADONLY Record
                # Specifies that the containing MODULE Record (section 2.3.4.2.3.2) is read-only.
                self.readonly = True
                reserved = struct.unpack("<L", dir_stream.read(4))[0]
                project.check_value(
                    'MODULEREADONLY_Reserved', 0x0000, reserved)
                section_id = struct.unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x0028:
                # 2.3.4.2.3.2.10 MODULEPRIVATE Record
                # Specifies that the containing MODULE Record (section 2.3.4.2.3.2) is only usable from within
                # the current VBA project.
                self.private = True
                reserved = struct.unpack("<L", dir_stream.read(4))[0]
                project.check_value('MODULEPRIVATE_Reserved', 0x0000, reserved)
                section_id = struct.unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x002B:  # TERMINATOR
                # Terminator (2 bytes): An unsigned integer that specifies the end of this record. MUST be 0x002B.
                # Reserved (4 bytes): MUST be 0x00000000. MUST be ignored.
                reserved = struct.unpack("<L", dir_stream.read(4))[0]
                project.check_value('MODULE_Reserved', 0x0000, reserved)
                section_id = None
            if section_id != None:
                log.warning(
                    'unknown or invalid module section id {0:04X}'.format(section_id))

            log.debug("Module Name = {0}".format(self.name_str))
            # log.debug("Module Name Unicode = {0}".format(self._name_unicode))
            log.debug("Stream Name = {0}".format(self.streamname_str))
            # log.debug("Stream Name Unicode = {0}".format(self._streamname_unicode))
            log.debug("TextOffset = {0}".format(self.textoffset))

            code_data = None
            # let's try the different names we have, just in case some are missing:
            try_names = (self.streamname, self._streamname_unicode,
                         self.name, self._name_unicode)
            for stream_name in try_names:
                # TODO: if olefile._find were less private, could replace this
                #        try-except with calls to it
                if stream_name is not None:
                    try:
                        self.code_path = project.vba_root + u'VBA/' + stream_name
                        log.debug('opening VBA code stream %s' %
                                  self.code_path)
                        code_data = project.ole.openstream(
                            self.code_path).read()
                        break
                    except IOError as ioe:
                        log.debug('failed to open stream VBA/%r (%r), try other name'
                                  % (stream_name, ioe))

            if code_data is None:
                log.info("Could not open stream %d of %d ('VBA/' + one of %r)!"
                         % (module_index, project.modules_count,
                            '/'.join("'" + stream_name + "'"
                                     for stream_name in try_names)))
                if project.relaxed:
                    return  # ... continue with next submodule
                else:
                    raise SubstreamOpenError('[BASE]', 'VBA/' + self.name)

            log.debug("length of code_data = {0}".format(len(code_data)))
            log.debug("offset of code_data = {0}".format(self.textoffset))
            code_data = code_data[self.textoffset:]
            if len(code_data) > 0:
                code_data = decompress_stream(bytearray(code_data))
                # store the raw code encoded as bytes with the project's code page:
                self.code_raw = code_data
                # decode it to unicode:
                self.code = project.decode_bytes(code_data)
                # also store a native str version:
                self.code_str = self.code
                # case-insensitive search in the code_modules dict to find the file extension:
                filext = self.project.module_ext.get(self.name.lower(), 'vba')
                self.filename = u'{0}.{1}'.format(self.name, filext)
                self.filename_str = self.filename
                log.debug('extracted file {0}'.format(self.filename_str))
            else:
                log.warning("module stream {0} has code data length 0".format(
                    self.streamname_str))
        except (UnexpectedDataError, SubstreamOpenError):
            raise
        except Exception as exc:
            log.info('Error parsing module {0} of {1}:'
                     .format(module_index, project.modules_count),
                     exc_info=True)
            if not project.relaxed:
                raise


class VBA_Project(object):
    """
    Class to parse a VBA project from an OLE file, and to store all the corresponding
    metadata and VBA modules.
    """

    def __init__(self, ole, vba_root, project_path, dir_path, relaxed=True):
        """
        Extract VBA macros from an OleFileIO object.

        :param vba_root: path to the VBA root storage, containing the VBA storage and the PROJECT stream
        :param project_path: path to the PROJECT stream
        :param relaxed: If True, only create info/debug log entry if data is not as expected
                        (e.g. opening substream fails); if False, raise an error in this case
        """
        self.ole = ole
        self.vba_root = vba_root
        self. project_path = project_path
        self.dir_path = dir_path
        self.relaxed = relaxed
        #: VBA modules contained in the project (list of VBA_Module objects)
        self.modules = []
        #: file extension for each VBA module
        self.module_ext = {}
        log.debug('Parsing the dir stream from %r' % dir_path)
        # read data from dir stream (compressed)
        dir_compressed = ole.openstream(dir_path).read()
        # decompress it:
        dir_stream = BytesIO(decompress_stream(bytearray(dir_compressed)))
        # store reference for later use:
        self.dir_stream = dir_stream

        # reference: MS-VBAL 2.3.4.2 dir Stream: Version Independent Project Information

        # PROJECTSYSKIND Record
        # Specifies the platform for which the VBA project is created.
        projectsyskind_id = struct.unpack("<H", dir_stream.read(2))[0]
        self.check_value('PROJECTSYSKIND_Id', 0x0001, projectsyskind_id)
        projectsyskind_size = struct.unpack("<L", dir_stream.read(4))[0]
        self.check_value('PROJECTSYSKIND_Size', 0x0004, projectsyskind_size)
        self.syskind = struct.unpack("<L", dir_stream.read(4))[0]
        SYSKIND_NAME = {
            0x00: "16-bit Windows",
            0x01: "32-bit Windows",
            0x02: "Macintosh",
            0x03: "64-bit Windows"
        }
        self.syskind_name = SYSKIND_NAME.get(self.syskind, 'Unknown')
        log.debug("PROJECTSYSKIND_SysKind: %d - %s" %
                  (self.syskind, self.syskind_name))
        if self.syskind not in SYSKIND_NAME:
            log.error(
                "invalid PROJECTSYSKIND_SysKind {0:04X}".format(self.syskind))

        # PROJECTLCID Record
        # Specifies the VBA project's LCID.
        projectlcid_id = struct.unpack("<H", dir_stream.read(2))[0]
        self.check_value('PROJECTLCID_Id', 0x0002, projectlcid_id)
        projectlcid_size = struct.unpack("<L", dir_stream.read(4))[0]
        self.check_value('PROJECTLCID_Size', 0x0004, projectlcid_size)
        # Lcid (4 bytes): An unsigned integer that specifies the LCID value for the VBA project. MUST be 0x00000409.
        self.lcid = struct.unpack("<L", dir_stream.read(4))[0]
        self.check_value('PROJECTLCID_Lcid', 0x409, self.lcid)

        # PROJECTLCIDINVOKE Record
        # Specifies an LCID value used for Invoke calls on an Automation server as specified in [MS-OAUT] section 3.1.4.4.
        projectlcidinvoke_id = struct.unpack("<H", dir_stream.read(2))[0]
        self.check_value('PROJECTLCIDINVOKE_Id', 0x0014, projectlcidinvoke_id)
        projectlcidinvoke_size = struct.unpack("<L", dir_stream.read(4))[0]
        self.check_value('PROJECTLCIDINVOKE_Size',
                         0x0004, projectlcidinvoke_size)
        # LcidInvoke (4 bytes): An unsigned integer that specifies the LCID value used for Invoke calls. MUST be 0x00000409.
        self.lcidinvoke = struct.unpack("<L", dir_stream.read(4))[0]
        self.check_value('PROJECTLCIDINVOKE_LcidInvoke',
                         0x409, self.lcidinvoke)

        # PROJECTCODEPAGE Record
        # Specifies the VBA project's code page.
        projectcodepage_id = struct.unpack("<H", dir_stream.read(2))[0]
        self.check_value('PROJECTCODEPAGE_Id', 0x0003, projectcodepage_id)
        projectcodepage_size = struct.unpack("<L", dir_stream.read(4))[0]
        self.check_value('PROJECTCODEPAGE_Size', 0x0002, projectcodepage_size)
        self.codepage = struct.unpack("<H", dir_stream.read(2))[0]
        self.codepage_name = codepages.get_codepage_name(self.codepage)
        log.debug('Project Code Page: %r - %s' %
                  (self.codepage, self.codepage_name))
        self.codec = codepages.codepage2codec(self.codepage)
        log.debug('Python codec corresponding to code page %d: %s' %
                  (self.codepage, self.codec))

        # PROJECTNAME Record
        # Specifies a unique VBA identifier as the name of the VBA project.
        projectname_id = struct.unpack("<H", dir_stream.read(2))[0]
        self.check_value('PROJECTNAME_Id', 0x0004, projectname_id)
        sizeof_projectname = struct.unpack("<L", dir_stream.read(4))[0]
        log.debug('Project name size: %d bytes' % sizeof_projectname)
        if sizeof_projectname < 1 or sizeof_projectname > 128:
            # TODO: raise an actual error? What is MS Office's behaviour?
            log.error(
                "PROJECTNAME_SizeOfProjectName value not in range [1-128]: {0}".format(sizeof_projectname))
        projectname_bytes = dir_stream.read(sizeof_projectname)
        self.projectname = self.decode_bytes(projectname_bytes)

        # PROJECTDOCSTRING Record
        # Specifies the description for the VBA project.
        projectdocstring_id = struct.unpack("<H", dir_stream.read(2))[0]
        self.check_value('PROJECTDOCSTRING_Id', 0x0005, projectdocstring_id)
        projectdocstring_sizeof_docstring = struct.unpack(
            "<L", dir_stream.read(4))[0]
        if projectdocstring_sizeof_docstring > 2000:
            log.error(
                "PROJECTDOCSTRING_SizeOfDocString value not in range: {0}".format(projectdocstring_sizeof_docstring))
        # DocString (variable): An array of SizeOfDocString bytes that specifies the description for the VBA project.
        # MUST contain MBCS characters encoded using the code page specified in PROJECTCODEPAGE (section 2.3.4.2.1.4).
        # MUST NOT contain null characters.
        docstring_bytes = dir_stream.read(projectdocstring_sizeof_docstring)
        self.docstring = self.decode_bytes(docstring_bytes)
        projectdocstring_reserved = struct.unpack("<H", dir_stream.read(2))[0]
        self.check_value('PROJECTDOCSTRING_Reserved',
                         0x0040, projectdocstring_reserved)
        projectdocstring_sizeof_docstring_unicode = struct.unpack(
            "<L", dir_stream.read(4))[0]
        if projectdocstring_sizeof_docstring_unicode % 2 != 0:
            log.error("PROJECTDOCSTRING_SizeOfDocStringUnicode is not even")
        # DocStringUnicode (variable): An array of SizeOfDocStringUnicode bytes that specifies the description for the
        # VBA project. MUST contain UTF-16 characters. MUST NOT contain null characters.
        # MUST contain the UTF-16 encoding of DocString.
        docstring_unicode_bytes = dir_stream.read(
            projectdocstring_sizeof_docstring_unicode)
        self.docstring_unicode = docstring_unicode_bytes.decode(
            'utf16', errors='replace')

        # PROJECTHELPFILEPATH Record - MS-OVBA 2.3.4.2.1.7
        projecthelpfilepath_id = struct.unpack("<H", dir_stream.read(2))[0]
        self.check_value('PROJECTHELPFILEPATH_Id',
                         0x0006, projecthelpfilepath_id)
        projecthelpfilepath_sizeof_helpfile1 = struct.unpack(
            "<L", dir_stream.read(4))[0]
        if projecthelpfilepath_sizeof_helpfile1 > 260:
            log.error(
                "PROJECTHELPFILEPATH_SizeOfHelpFile1 value not in range: {0}".format(projecthelpfilepath_sizeof_helpfile1))
        projecthelpfilepath_helpfile1 = dir_stream.read(
            projecthelpfilepath_sizeof_helpfile1)
        projecthelpfilepath_reserved = struct.unpack(
            "<H", dir_stream.read(2))[0]
        self.check_value('PROJECTHELPFILEPATH_Reserved',
                         0x003D, projecthelpfilepath_reserved)
        projecthelpfilepath_sizeof_helpfile2 = struct.unpack(
            "<L", dir_stream.read(4))[0]
        if projecthelpfilepath_sizeof_helpfile2 != projecthelpfilepath_sizeof_helpfile1:
            log.error(
                "PROJECTHELPFILEPATH_SizeOfHelpFile1 does not equal PROJECTHELPFILEPATH_SizeOfHelpFile2")
        projecthelpfilepath_helpfile2 = dir_stream.read(
            projecthelpfilepath_sizeof_helpfile2)
        if projecthelpfilepath_helpfile2 != projecthelpfilepath_helpfile1:
            log.error(
                "PROJECTHELPFILEPATH_HelpFile1 does not equal PROJECTHELPFILEPATH_HelpFile2")

        # PROJECTHELPCONTEXT Record
        projecthelpcontext_id = struct.unpack("<H", dir_stream.read(2))[0]
        self.check_value('PROJECTHELPCONTEXT_Id',
                         0x0007, projecthelpcontext_id)
        projecthelpcontext_size = struct.unpack("<L", dir_stream.read(4))[0]
        self.check_value('PROJECTHELPCONTEXT_Size',
                         0x0004, projecthelpcontext_size)
        projecthelpcontext_helpcontext = struct.unpack(
            "<L", dir_stream.read(4))[0]
        unused = projecthelpcontext_helpcontext

        # PROJECTLIBFLAGS Record
        projectlibflags_id = struct.unpack("<H", dir_stream.read(2))[0]
        self.check_value('PROJECTLIBFLAGS_Id', 0x0008, projectlibflags_id)
        projectlibflags_size = struct.unpack("<L", dir_stream.read(4))[0]
        self.check_value('PROJECTLIBFLAGS_Size', 0x0004, projectlibflags_size)
        projectlibflags_projectlibflags = struct.unpack(
            "<L", dir_stream.read(4))[0]
        self.check_value('PROJECTLIBFLAGS_ProjectLibFlags',
                         0x0000, projectlibflags_projectlibflags)

        # PROJECTVERSION Record
        projectversion_id = struct.unpack("<H", dir_stream.read(2))[0]
        self.check_value('PROJECTVERSION_Id', 0x0009, projectversion_id)
        projectversion_reserved = struct.unpack("<L", dir_stream.read(4))[0]
        self.check_value('PROJECTVERSION_Reserved',
                         0x0004, projectversion_reserved)
        projectversion_versionmajor = struct.unpack(
            "<L", dir_stream.read(4))[0]
        projectversion_versionminor = struct.unpack(
            "<H", dir_stream.read(2))[0]
        unused = projectversion_versionmajor
        unused = projectversion_versionminor

        # PROJECTCONSTANTS Record
        projectconstants_id = struct.unpack("<H", dir_stream.read(2))[0]
        self.check_value('PROJECTCONSTANTS_Id', 0x000C, projectconstants_id)
        projectconstants_sizeof_constants = struct.unpack(
            "<L", dir_stream.read(4))[0]
        if projectconstants_sizeof_constants > 1015:
            log.error(
                "PROJECTCONSTANTS_SizeOfConstants value not in range: {0}".format(projectconstants_sizeof_constants))
        projectconstants_constants = dir_stream.read(
            projectconstants_sizeof_constants)
        projectconstants_reserved = struct.unpack("<H", dir_stream.read(2))[0]
        self.check_value('PROJECTCONSTANTS_Reserved',
                         0x003C, projectconstants_reserved)
        projectconstants_sizeof_constants_unicode = struct.unpack(
            "<L", dir_stream.read(4))[0]
        if projectconstants_sizeof_constants_unicode % 2 != 0:
            log.error("PROJECTCONSTANTS_SizeOfConstantsUnicode is not even")
        projectconstants_constants_unicode = dir_stream.read(
            projectconstants_sizeof_constants_unicode)
        unused = projectconstants_constants
        unused = projectconstants_constants_unicode

        # array of REFERENCE records
        # Specifies a reference to an Automation type library or VBA project.
        check = None
        while True:
            check = struct.unpack("<H", dir_stream.read(2))[0]
            log.debug("reference type = {0:04X}".format(check))
            if check == 0x000F:
                break

            if check == 0x0016:
                # REFERENCENAME
                # Specifies the name of a referenced VBA project or Automation type library.
                reference_id = check
                reference_sizeof_name = struct.unpack(
                    "<L", dir_stream.read(4))[0]
                reference_name = dir_stream.read(reference_sizeof_name)
                log.debug('REFERENCE name: %s' %
                          self.decode_bytes(reference_name))
                reference_reserved = struct.unpack("<H", dir_stream.read(2))[0]
                # According to [MS-OVBA] 2.3.4.2.2.2 REFERENCENAME Record:
                # "Reserved (2 bytes): MUST be 0x003E. MUST be ignored."
                # So let's ignore it, otherwise it crashes on some files (issue #132)
                # PR #135 by @c1fe:
                # contrary to the specification I think that the unicode name
                # is optional. if reference_reserved is not 0x003E I think it
                # is actually the start of another REFERENCE record
                # at least when projectsyskind_syskind == 0x02 (Macintosh)
                if reference_reserved == 0x003E:
                    # if reference_reserved not in (0x003E, 0x000D):
                    #    raise UnexpectedDataError(dir_path, 'REFERENCE_Reserved',
                    #                              0x0003E, reference_reserved)
                    reference_sizeof_name_unicode = struct.unpack(
                        "<L", dir_stream.read(4))[0]
                    reference_name_unicode = dir_stream.read(
                        reference_sizeof_name_unicode)
                    unused = reference_id
                    unused = reference_name
                    unused = reference_name_unicode
                    continue
                else:
                    check = reference_reserved
                    log.debug("reference type = {0:04X}".format(check))

            if check == 0x0033:
                # REFERENCEORIGINAL (followed by REFERENCECONTROL)
                # Specifies the identifier of the Automation type library the containing REFERENCECONTROL's
                # (section 2.3.4.2.2.3) twiddled type library was generated from.
                referenceoriginal_id = check
                referenceoriginal_sizeof_libidoriginal = struct.unpack(
                    "<L", dir_stream.read(4))[0]
                referenceoriginal_libidoriginal = dir_stream.read(
                    referenceoriginal_sizeof_libidoriginal)
                log.debug('REFERENCE original lib id: %s' %
                          self.decode_bytes(referenceoriginal_libidoriginal))
                unused = referenceoriginal_id
                unused = referenceoriginal_libidoriginal
                continue

            if check == 0x002F:
                # REFERENCECONTROL
                # Specifies a reference to a twiddled type library and its extended type library.
                referencecontrol_id = check
                referencecontrol_sizetwiddled = struct.unpack(
                    "<L", dir_stream.read(4))[0]  # ignore
                referencecontrol_sizeof_libidtwiddled = struct.unpack(
                    "<L", dir_stream.read(4))[0]
                referencecontrol_libidtwiddled = dir_stream.read(
                    referencecontrol_sizeof_libidtwiddled)
                log.debug('REFERENCE control twiddled lib id: %s' %
                          self.decode_bytes(referencecontrol_libidtwiddled))
                referencecontrol_reserved1 = struct.unpack(
                    "<L", dir_stream.read(4))[0]  # ignore
                self.check_value('REFERENCECONTROL_Reserved1',
                                 0x0000, referencecontrol_reserved1)
                referencecontrol_reserved2 = struct.unpack(
                    "<H", dir_stream.read(2))[0]  # ignore
                self.check_value('REFERENCECONTROL_Reserved2',
                                 0x0000, referencecontrol_reserved2)
                unused = referencecontrol_id
                unused = referencecontrol_sizetwiddled
                unused = referencecontrol_libidtwiddled
                # optional field
                check2 = struct.unpack("<H", dir_stream.read(2))[0]
                if check2 == 0x0016:
                    referencecontrol_namerecordextended_id = check
                    referencecontrol_namerecordextended_sizeof_name = struct.unpack(
                        "<L", dir_stream.read(4))[0]
                    referencecontrol_namerecordextended_name = dir_stream.read(
                        referencecontrol_namerecordextended_sizeof_name)
                    log.debug('REFERENCE control name record extended: %s' %
                              self.decode_bytes(referencecontrol_namerecordextended_name))
                    referencecontrol_namerecordextended_reserved = struct.unpack(
                        "<H", dir_stream.read(2))[0]
                    if referencecontrol_namerecordextended_reserved == 0x003E:
                        referencecontrol_namerecordextended_sizeof_name_unicode = struct.unpack(
                            "<L", dir_stream.read(4))[0]
                        referencecontrol_namerecordextended_name_unicode = dir_stream.read(
                            referencecontrol_namerecordextended_sizeof_name_unicode)
                        referencecontrol_reserved3 = struct.unpack(
                            "<H", dir_stream.read(2))[0]
                        unused = referencecontrol_namerecordextended_id
                        unused = referencecontrol_namerecordextended_name
                        unused = referencecontrol_namerecordextended_name_unicode
                    else:
                        referencecontrol_reserved3 = referencecontrol_namerecordextended_reserved
                else:
                    referencecontrol_reserved3 = check2

                self.check_value('REFERENCECONTROL_Reserved3',
                                 0x0030, referencecontrol_reserved3)
                referencecontrol_sizeextended = struct.unpack(
                    "<L", dir_stream.read(4))[0]
                referencecontrol_sizeof_libidextended = struct.unpack(
                    "<L", dir_stream.read(4))[0]
                referencecontrol_libidextended = dir_stream.read(
                    referencecontrol_sizeof_libidextended)
                referencecontrol_reserved4 = struct.unpack(
                    "<L", dir_stream.read(4))[0]
                referencecontrol_reserved5 = struct.unpack(
                    "<H", dir_stream.read(2))[0]
                referencecontrol_originaltypelib = dir_stream.read(16)
                referencecontrol_cookie = struct.unpack(
                    "<L", dir_stream.read(4))[0]
                unused = referencecontrol_sizeextended
                unused = referencecontrol_libidextended
                unused = referencecontrol_reserved4
                unused = referencecontrol_reserved5
                unused = referencecontrol_originaltypelib
                unused = referencecontrol_cookie
                continue

            if check == 0x000D:
                # REFERENCEREGISTERED
                # Specifies a reference to an Automation type library.
                referenceregistered_id = check
                referenceregistered_size = struct.unpack(
                    "<L", dir_stream.read(4))[0]
                referenceregistered_sizeof_libid = struct.unpack(
                    "<L", dir_stream.read(4))[0]
                referenceregistered_libid = dir_stream.read(
                    referenceregistered_sizeof_libid)
                log.debug('REFERENCE registered lib id: %s' %
                          self.decode_bytes(referenceregistered_libid))
                referenceregistered_reserved1 = struct.unpack(
                    "<L", dir_stream.read(4))[0]
                self.check_value('REFERENCEREGISTERED_Reserved1',
                                 0x0000, referenceregistered_reserved1)
                referenceregistered_reserved2 = struct.unpack(
                    "<H", dir_stream.read(2))[0]
                self.check_value('REFERENCEREGISTERED_Reserved2',
                                 0x0000, referenceregistered_reserved2)
                unused = referenceregistered_id
                unused = referenceregistered_size
                unused = referenceregistered_libid
                continue

            if check == 0x000E:
                # REFERENCEPROJECT
                # Specifies a reference to an external VBA project.
                referenceproject_id = check
                referenceproject_size = struct.unpack(
                    "<L", dir_stream.read(4))[0]
                referenceproject_sizeof_libidabsolute = struct.unpack(
                    "<L", dir_stream.read(4))[0]
                referenceproject_libidabsolute = dir_stream.read(
                    referenceproject_sizeof_libidabsolute)
                log.debug('REFERENCE project lib id absolute: %s' %
                          self.decode_bytes(referenceproject_libidabsolute))
                referenceproject_sizeof_libidrelative = struct.unpack(
                    "<L", dir_stream.read(4))[0]
                referenceproject_libidrelative = dir_stream.read(
                    referenceproject_sizeof_libidrelative)
                log.debug('REFERENCE project lib id relative: %s' %
                          self.decode_bytes(referenceproject_libidrelative))
                referenceproject_majorversion = struct.unpack(
                    "<L", dir_stream.read(4))[0]
                referenceproject_minorversion = struct.unpack(
                    "<H", dir_stream.read(2))[0]
                unused = referenceproject_id
                unused = referenceproject_size
                unused = referenceproject_libidabsolute
                unused = referenceproject_libidrelative
                unused = referenceproject_majorversion
                unused = referenceproject_minorversion
                continue

            log.error('invalid or unknown check Id {0:04X}'.format(check))
            # raise an exception instead of stopping abruptly (issue #180)
            raise UnexpectedDataError(
                dir_path, 'reference type', (0x0F, 0x16, 0x33, 0x2F, 0x0D, 0x0E), check)
            # sys.exit(0)

    def check_value(self, name, expected, value):
        if expected != value:
            if self.relaxed:
                log.error("invalid value for {0} expected {1:04X} got {2:04X}"
                          .format(name, expected, value))
            else:
                raise UnexpectedDataError(self.dir_path, name, expected, value)

    def parse_project_stream(self):
        """
        Parse the PROJECT stream from the VBA project
        :return:
        """
        # Open the PROJECT stream:
        # reference: [MS-OVBA] 2.3.1 PROJECT Stream
        project_stream = self.ole.openstream(self.project_path)

        # sample content of the PROJECT stream:

        # ID="{5312AC8A-349D-4950-BDD0-49BE3C4DD0F0}"
        # Document=ThisDocument/&H00000000
        # Module=NewMacros
        # Name="Project"
        # HelpContextID="0"
        # VersionCompatible32="393222000"
        # CMG="F1F301E705E705E705E705"
        # DPB="8F8D7FE3831F2020202020"
        # GC="2D2FDD81E51EE61EE6E1"
        ##
        # [Host Extender Info]
        # &H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000
        # &H00000002={000209F2-0000-0000-C000-000000000046};Word8.0;&H00000000
        ##
        # [Workspace]
        # ThisDocument=22, 29, 339, 477, Z
        # NewMacros=-4, 42, 832, 510, C

        self.module_ext = {}

        for line in project_stream:
            line = self.decode_bytes(line)
            log.debug('PROJECT: %r' % line)
            line = line.strip()
            if '=' in line:
                # split line at the 1st equal sign:
                name, value = line.split('=', 1)
                # looking for code modules
                # add the code module as a key in the dictionary
                # the value will be the extension needed later
                # The value is converted to lowercase, to allow case-insensitive matching (issue #3)
                value = value.lower()
                if name == 'Document':
                    # split value at the 1st slash, keep 1st part:
                    value = value.split('/', 1)[0]
                    self.module_ext[value] = CLASS_EXTENSION
                elif name == 'Module':
                    self.module_ext[value] = MODULE_EXTENSION
                elif name == 'Class':
                    self.module_ext[value] = CLASS_EXTENSION
                elif name == 'BaseClass':
                    self.module_ext[value] = FORM_EXTENSION

    def parse_modules(self):
        dir_stream = self.dir_stream
        # projectmodules_id has already been read by the previous loop = 0x000F
        # projectmodules_id = check  #struct.unpack("<H", dir_stream.read(2))[0]
        # self.check_value('PROJECTMODULES_Id', 0x000F, projectmodules_id)
        projectmodules_size = struct.unpack("<L", dir_stream.read(4))[0]
        self.check_value('PROJECTMODULES_Size', 0x0002, projectmodules_size)
        self.modules_count = struct.unpack("<H", dir_stream.read(2))[0]
        _id = struct.unpack("<H", dir_stream.read(2))[0]
        self.check_value('PROJECTMODULES_ProjectCookieRecord_Id', 0x0013, _id)
        size = struct.unpack("<L", dir_stream.read(4))[0]
        self.check_value(
            'PROJECTMODULES_ProjectCookieRecord_Size', 0x0002, size)
        projectcookierecord_cookie = struct.unpack("<H", dir_stream.read(2))[0]
        unused = projectcookierecord_cookie

        log.debug("parsing {0} modules".format(self.modules_count))
        for module_index in range(0, self.modules_count):
            module = VBA_Module(self, self.dir_stream,
                                module_index=module_index)
            self.modules.append(module)
            yield (module.code_path, module.filename_str, module.code_str)
        _ = unused   # make pylint happy: now variable "unused" is being used ;-)
        return

    def decode_bytes(self, bytes_string, errors='replace'):
        """
        Decode a bytes string to a unicode string, using the project code page
        :param bytes_string: bytes, bytes string to be decoded
        :param errors: str, mode to handle unicode conversion errors
        :return: str/unicode, decoded string
        """
        return bytes_string.decode(self.codec, errors=errors)


class VBA_RUN(object):
    def __init__(self):
        self.ole = None

    def is_ole(self, content):
        return olefile.isOleFile(content)

    def check_vba_stream(self, vba_root, stream_path):
        full_path = vba_root + stream_path
        if self.ole.exists(full_path) and self.ole.get_type(full_path) == olefile.STGTY_STREAM:
            return full_path
        else:
            return False

    def get_vba_projects(self):
        # start with an empty list:
        vba_projects = []
        # Look for any storage containing those storage/streams:
        for storage in self.ole.listdir(streams=False, storages=True):
            # Look for a storage ending with "VBA":
            if storage[-1].upper() == 'VBA':
                vba_root = '/'.join(storage[:-1])
                # Add a trailing slash to vba_root, unless it is the root of the OLE file:
                # (used later to append all the child streams/storages)
                if vba_root != '':
                    vba_root += '/'

                # Check if the VBA root storage also contains a PROJECT stream:
                project_path = self.check_vba_stream(vba_root, 'PROJECT')
                if not project_path:
                    continue
                # Check if the VBA root storage also contains a VBA/_VBA_PROJECT stream:
                vba_project_path = self.check_vba_stream(
                    vba_root, 'VBA/_VBA_PROJECT')
                if not vba_project_path:
                    continue
                # Check if the VBA root storage also contains a VBA/dir stream:
                dir_path = self.check_vba_stream(vba_root, 'VBA/dir')
                if not dir_path:
                    continue
                # Now we are pretty sure it is a VBA project structure
                # append the results to the list as a tuple for later use:
                vba_projects.append((vba_root, project_path, dir_path))
        return vba_projects

    def _extract_vba(self, vba_root, project_path, dir_path, relaxed=True):
        """
        Extract VBA macros from an OleFileIO object.
        Internal function, do not call directly.

        vba_root: path to the VBA root storage, containing the VBA storage and the PROJECT stream
        vba_project: path to the PROJECT stream
        :param relaxed: If True, only create info/debug log entry if data is not as expected
                        (e.g. opening substream fails); if False, raise an error in this case
        This is a generator, yielding (stream path, VBA filename, VBA source code) for each VBA code stream
        """

        project = VBA_Project(self.ole, vba_root,
                              project_path, dir_path, relaxed)
        project.parse_project_stream()

        for code_path, filename, code_data in project.parse_modules():
            yield (code_path, filename, code_data)

    def parse(self, file_content):
        if olefile.isOleFile(file_content):
            self.ole = olefile.OleFileIO(file_content)
            vba_projects = self.get_vba_projects()
            for vba_root, project_path, dir_path in vba_projects:
                # extract all VBA macros from that VBA root storage:
                # The function _extract_vba may fail on some files (issue #132)
                try:
                    for stream_path, vba_filename, vba_code in self._extract_vba(vba_root, project_path, dir_path, True):
                        yield {"stream_path": stream_path, "vba_filename": vba_filename, "vba_code": vba_code.encode()}
                except Exception as e:
                    log.exception('Error in _extract_vba')
