#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# Copyright (c) 2020 Nicolas Iooss
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""Parse the version information from the resources of a PE file

@author: Nicolas Iooss
@license: MIT
"""
import collections
import ctypes
import logging
import re
import struct

# pylint: disable=invalid-name
logger = logging.getLogger(__name__)


class struct_vs_fixedfileinfo(ctypes.Structure):
    """VS_FIXEDFILEINFO"""
    _fields_ = [
        ('dwSignature', ctypes.c_uint32),
        ('dwStrucVersion', ctypes.c_uint32),
        ('dwFileVersionMS', ctypes.c_uint32),
        ('dwFileVersionLS', ctypes.c_uint32),
        ('dwProductVersionMS', ctypes.c_uint32),
        ('dwProductVersionLS', ctypes.c_uint32),
        ('dwFileFlagsMask', ctypes.c_uint32),
        ('dwFileFlags', ctypes.c_uint32),
        ('dwFileOS', ctypes.c_uint32),
        ('dwFileType', ctypes.c_uint32),
        ('dwFileSubtype', ctypes.c_uint32),
        ('dwFileDateMS', ctypes.c_uint32),
        ('dwFileDateLS', ctypes.c_uint32),
    ]


assert ctypes.sizeof(struct_vs_fixedfileinfo) == 0x34


class VsVersionInfo:
    """Version information from the resources of a PE file

    A VS_VERSION_INFO structure contains:
    * a header with "VS_VERSION_INFO"
    * a VS_FIXEDFILEINFO structure
    * a StringFileInfo section with strings
    * a VarFileInfo section that gives the languages that exist in StringFileInfo

    Documentation:
    * https://docs.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource
    * https://docs.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
    """
    STRING_FIELDS = frozenset((
        'APIVersion',
        'ActiveMovie',
        'Additional Notes',
        'Applies to',
        'Assembly Version',
        'AssemblyVersion',
        'Baseline',
        'BranchName',
        'Build Date',
        'Build Description',
        'Build Number',
        'Build Version',
        'BuildDate',
        'BuildDefinition',
        'BuildID',
        'Built by',
        'CPU',
        'Changelist',
        'Comment',
        'Comments',
        'Company',
        'CompanyName',
        'CompiledScript',
        'ComtradeViewer',
        'Contact',
        'DataVersion1',
        'DataVersion2',
        'DataVersion3',
        'Description',
        'Developer',
        'DirectShow',
        'DivisionName',
        'EngineVersion',
        'FileDescription',
        'FileExtents',
        'FileFlags',
        'FileOpenName',
        'FileVersion',
        'Full Version',
        'GenerationDate',
        'GoldenBits',
        'Info',
        'Installation Type',
        'Installer Engine',
        'Installer Version',
        'Interface Version',
        'Internal Build Number',
        'InternalName',
        'InternetSite',
        'ISInternalVersion',
        'KB Article Number',
        'Language',
        'LegalCopyright',
        'LegalTrademark1',
        'LegalTradeMarks',
        'LegalTrademarks',
        'LegalTrademarks1',
        'LegalTrademarks2',
        'Licence',
        'License',
        'MIMEType',
        'MoreInfoUrl',
        'OLESelfRegister',
        'OleSelfRegister',
        'Operating System',
        'Original File name',
        'OriginalDate',
        'OriginalFileName',  # Uncommon
        'OriginalFilename',
        'Package Type',
        'Package Version',
        'Platform',
        'Private Build',
        'PrivateBuild',
        'Proc. Architecture',
        'Processor',
        'ProductDate',
        'ProductFamily',
        'ProductFileFlags',
        'ProductName',
        'ProductVersion',
        'ReleaseType',
        'RegistryKey',
        'Self-Extractor Version',
        'SharedMemoryVersion',
        'SourceId',
        'SpecialBuild',
        'StubName',
        'StubVersion',
        'Support Link',
        'SupportedLanguages',
        'VersionDate',
        'WWW',
        'gSOAP Copyright',
    ))

    def __init__(self, content):
        self.content = content

        # Parse the header
        length, value_len, is_text, key, offset = self.parse_header(0)
        if length < len(content):
            # Ensure that there is padding with zero
            if any(x != 0 for x in content[length:]):
                # Sometimes, there is some content!
                # Seen for example with some Toshiba executables
                if len(content) >= length + 5 and content[length:] == b'FE2X' + b'\0' * (len(content) - length - 4):
                    pass
                else:
                    logger.warning("Unexpected non-null padding in VS_VERSION_INFO: %r", content[length:])
        elif length > len(content):
            raise ValueError("Unexpected large content length: {:#x} + 8 != {:#x}".format(length, len(content)))
        if value_len != 0x34:
            raise ValueError("Unexpected value length: {:#x} != 0x34".format(value_len))
        if is_text:
            raise ValueError("Unexpected is_text for VS_VERSION_INFO")
        if key != 'VS_VERSION_INFO':
            raise ValueError("Unexpected key for VS_VERSION_INFO: {}".format(repr(key)))

        # Parse structure VS_FIXEDFILEINFO
        self.fixed = struct_vs_fixedfileinfo.from_buffer_copy(content, offset)
        offset += 0x34
        if self.fixed.dwSignature != 0xfeef04bd:
            raise ValueError("Unexpected signature for VS_FIXEDFILEINFO: {:#x}".format(self.fixed.dwSignature))
        if self.fixed.dwStrucVersion != 0x10000:
            if self.fixed.dwStrucVersion != 0:  # Some programs use version 0
                raise ValueError("Unexpected structure version for VS_FIXEDFILEINFO: {:#x}".format(
                    self.fixed.dwStrucVersion))
        if self.fixed.dwFileOS not in (4, 0x40000, 0x40004):  # VOS__WINDOWS32 or VOS_NT or VOS_NT_WINDOWS32
            if self.fixed.dwFileOS not in (0, 0x10001, 0x10004):
                # Some files use unknown or VOS_DOS_WINDOWS16 or VOS_DOS_WINDOWS32
                raise ValueError("Unexpected file OS for VS_FIXEDFILEINFO: {:#x}".format(self.fixed.dwFileOS))

        self.file_version = '{}.{}.{}.{}'.format(
            self.fixed.dwFileVersionMS >> 16,
            self.fixed.dwFileVersionMS & 0xffff,
            self.fixed.dwFileVersionLS >> 16,
            self.fixed.dwFileVersionLS & 0xffff,
        )
        self.product_version = '{}.{}.{}.{}'.format(
            self.fixed.dwProductVersionMS >> 16,
            self.fixed.dwProductVersionMS & 0xffff,
            self.fixed.dwProductVersionLS >> 16,
            self.fixed.dwProductVersionLS & 0xffff,
        )

        self.children = collections.OrderedDict()
        while offset < length:
            key, value, offset = self.parse_root_child(offset)
            if key in self.children:
                # Duplicate subkey might occur, with the same content
                if value != self.children[key]:
                    raise ValueError("Duplicated root child {} in Version info: {}".format(
                        repr(key), repr(value)))
            self.children[key] = value

        self.var_translation = None
        if 'VarFileInfo' in self.children:
            if 'Translation' not in self.children['VarFileInfo']:
                raise ValueError("Missing Translation in Version Info VarFileInfo: {}".format(
                    repr(self.children)))
            var_translation = self.children['VarFileInfo']['Translation']
            if not isinstance(var_translation, bytes):
                # It is a decoded tuple
                assert len(var_translation) == 2
                self.var_translation = var_translation

        if 'StringFileInfo' in self.children:
            if self.var_translation is not None:
                if sorted(self.children.keys()) != ['StringFileInfo', 'VarFileInfo']:
                    raise ValueError("Unexpected Version Info child strings: {}".format(
                        repr(self.children)))
                lang, codepage = self.var_translation
                self.var_translation_hex = '{:04X}{:04X}'.format(lang, codepage)
                if self.var_translation_hex not in self.children['StringFileInfo']:
                    self.var_translation_hex = '{:04X}{:04x}'.format(lang, codepage)
                    if self.var_translation_hex not in self.children['StringFileInfo']:
                        self.var_translation_hex = '{:04x}{:04x}'.format(lang, codepage)
                        if self.var_translation_hex not in self.children['StringFileInfo']:
                            if len(self.children['StringFileInfo']) == 1:
                                self.var_translation_hex = list(self.children['StringFileInfo'].keys())[0]
                if self.var_translation_hex not in self.children['StringFileInfo'] and lang == 0:
                    # Try en_US by default
                    lang = 0x0409
                    self.var_translation_hex = '{:04X}{:04X}'.format(lang, codepage)
                    if self.var_translation_hex not in self.children['StringFileInfo']:
                        self.var_translation_hex = '{:04X}{:04x}'.format(lang, codepage)
                        if self.var_translation_hex not in self.children['StringFileInfo']:
                            self.var_translation_hex = '{:04x}{:04x}'.format(lang, codepage)
            else:
                # Use the first child of StringFileInfo by default
                self.var_translation_hex = list(self.children['StringFileInfo'].keys())[0]
            if self.var_translation_hex not in self.children['StringFileInfo']:
                raise ValueError("Unable to find Translation entry {} into StringFileInfo {}".format(
                    self.var_translation_hex, list(self.children['StringFileInfo'].keys())))
            self.string_file_info = self.children['StringFileInfo'][self.var_translation_hex]
        elif all(key in self.STRING_FIELDS for key in self.children):
            self.var_translation_hex = None
            self.string_file_info = self.children
        else:
            raise ValueError("Unexpected root fields in parsed version info: {}".format(self.children))

        self.file_version_str = self.string_file_info.get('FileVersion')
        self.product_version_str = self.string_file_info.get('ProductVersion')

        # The string and binary versions have nothing to do one with another.
        # Do NOT try to compare them:
        # * aspnet_counters.dll uses "4.6.1586.0 built by: NETFXREL2"
        # * advpack.dll uses "11.00.14393.0 (rs1_release.160715-1616)" (with .00)
        # * atl.dll uses "3.05.2284", a .0 is missing
        # * atmfd.dll uses "5.1 Build 250" for 5.1.2.250
        # etc.

        self.internal_name = self.string_file_info.get('InternalName', '').strip('"')
        self.original_file_name = self.string_file_info.get('OriginalFilename', '').strip('"')
        self.company_name = self.string_file_info.get('CompanyName', '')
        self.file_description = self.string_file_info.get('FileDescription', '')

        # Remove really horrible things in internal name, such as in
        # C:/Windows/System32/drivers/evbda.sys : 'evbda.sys"\r\nFW Ver:7.13.1.0\r\nFW Compile:1'
        if '"\r\n' in self.internal_name:
            self.internal_name = self.internal_name[:self.internal_name.index('"\r\n')]

        # if not re.match(r'^[-0-9a-zA-Z._ ():;,<>]*$', self.internal_name):
        #     raise ValueError("Unexpected characters in internal name: {}".format(
        #         repr(self.internal_name)))
        if not re.match(r'^[-0-9a-zA-Zé._ (),+*®?]*$', self.original_file_name):
            logger.warning("Unexpected characters in original file name: %r", self.original_file_name)
            self.original_file_name = ''
        # if not re.match(r'^[-0-9a-zA-Z., ()®:/]*$', self.company_name):
        #     raise ValueError("Unexpected characters in company name: {}".format(
        #         repr(self.company_name)))

        # In fact, there are many complex usecases when comparing original
        # file and internal names, like 'AuditPolMsg.DLL' != 'AuditPolSnapInMsg',
        # or 'Software Installation Editor Snapin'. So do not check consistency.

    @staticmethod
    def align_offset(offset):
        """Align the offset on 4 bytes"""
        if offset & 3:
            return offset + 4 - (offset & 3)
        return offset

    def parse_header(self, offset):
        """Parse (wLength, wValueLength, wType, wszKey) header"""
        length, value_len, is_text = struct.unpack('<HHH', self.content[offset:offset + 6])
        if is_text not in (0, 1):
            raise ValueError("Unexpected value for is_text (0=binary, 1=text): {}".format(is_text))
        key_end = offset + 6
        while True:
            key_end = self.content.find(b'\0\0', key_end)
            if key_end & 1:
                # Ensure that we found "\0" as UTF-16 character
                key_end += 1
                continue
            break
        key = self.content[offset + 6:key_end].decode('utf-16le')
        return length, value_len, is_text != 0, key, self.align_offset(key_end + 2)

    def parse_root_child(self, base_offset):
        """Parse a StringFileInfo or a VarFileInfo entry"""
        length, value_len, is_text, key, new_offset = self.parse_header(base_offset)
        offset_limit = base_offset + length
        if key == 'STRINGFILEINFO':
            key = 'StringFileInfo'
        if key == 'VARFILEINFO':
            key = 'VarFileInfo'

        if key == 'StringFileInfo':
            # Parse StringFileInfo section
            if value_len:
                raise ValueError("Unexpected value_len for StringFileInfo")
            children = collections.OrderedDict()
            while new_offset < offset_limit:
                subkey, value, new_offset = self.parse_string_table(new_offset)
                while subkey in children:
                    # Duplicate subkey might occur, but should be infrequent
                    subkey += '_'
                children[subkey] = value
            return key, children, self.align_offset(offset_limit)

        if key == 'VarFileInfo':
            # Parse VarFileInfo section
            if value_len:
                raise ValueError("Unexpected value_len for VarFileInfo")
            children = collections.OrderedDict()
            while new_offset < offset_limit:
                subkey, value, new_offset = self.parse_var(new_offset)
                assert subkey not in children
                children[subkey] = value
            return key, children, self.align_offset(offset_limit)

        if key in self.STRING_FIELDS:
            # Piggy-back on string structure
            return self.parse_string_struct(base_offset)

        logger.error("Unimplemented version info data: %r", self.content)
        logger.error("... at offset %#x: %r", base_offset, self.content[base_offset:])
        raise NotImplementedError("Unimplemented root child {}".format(repr(key)))

    def parse_string_table(self, base_offset):
        """Parse a StringTable from a StringFileInfo"""
        length, value_len, is_text, key, new_offset = self.parse_header(base_offset)
        offset_limit = base_offset + length
        if value_len:
            raise ValueError("Unexpected value_len for StringTable")
        children = collections.OrderedDict()
        while new_offset < offset_limit:
            subkey, value, new_offset = self.parse_string_struct(new_offset)
            if subkey in children:
                # Duplicate subkey might occur, with the same content
                if value != children[subkey]:
                    raise ValueError("Duplicated string {} in Version info: {}".format(
                        repr(subkey), repr(value)))
            children[subkey] = value
        return key, children, self.align_offset(offset_limit)

    def parse_string_struct(self, base_offset):
        """Parse a StringStruct from a StringFileInfo/StringTable"""
        length, value_len, is_text, key, new_offset = self.parse_header(base_offset)
        offset_limit = base_offset + length

        if key not in self.STRING_FIELDS:
            upper_string_fields = {field.upper(): field for field in sorted(self.STRING_FIELDS)}
            if key in upper_string_fields:
                # Convert "COMPANYNAME" to "CompanyName"
                key = upper_string_fields[key]
            else:
                raise ValueError("Unknown string name in version info: {}".format(repr(key)))

        if is_text:
            end_offset = new_offset + 2 * value_len
        else:
            end_offset = new_offset + value_len
        # Some ill-formed versions go past the limit...
        if end_offset > offset_limit:
            end_offset = offset_limit
        value = self.content[new_offset:end_offset].decode('utf-16le').rstrip('\0')
        new_offset = self.align_offset(end_offset)

        if new_offset != self.align_offset(offset_limit):
            raise ValueError("Unexpected children for StringStruct: {:#x} != align({:#x})".format(
                new_offset, offset_limit))
        return key, value, new_offset

    def parse_var(self, base_offset):
        """Parse a Var from a VarFileInfo"""
        length, value_len, is_text, key, new_offset = self.parse_header(base_offset)
        offset_limit = base_offset + length
        if is_text:
            raise ValueError("Unexpected is_text for Var")

        if key == 'TRANSLATION':
            key = 'Translation'

        value = self.content[new_offset:new_offset + value_len]
        if key == 'Translation' and value_len == 4:
            lang, codepage = struct.unpack('<HH', value)
            value = (lang, codepage)

        new_offset = self.align_offset(new_offset + value_len)
        if new_offset != self.align_offset(offset_limit):
            raise ValueError("Unexpected children for Var")
        return key, value, new_offset


if __name__ == '__main__':
    from pathlib import Path
    import sys

    sys.path.insert(0, Path(__file__).parent)
    import pe_structs

    logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)
    for file_path in sys.argv[1:]:
        pe_file = pe_structs.PEFile(Path(file_path))
        ver_info = pe_file.resource_version_info
        if not ver_info:
            logger.warning("No version information found in %s", file_path)
            continue

        print("{}:".format(file_path))
        print("  * Fixed file info:")
        pe_structs.dump_struct(ver_info.fixed, indent='    ')
        print("  * File version: {}".format(ver_info.file_version))
        print("  * Product version: {}".format(ver_info.product_version))
        pe_structs.dump_dict(ver_info.children, indent='  ')
