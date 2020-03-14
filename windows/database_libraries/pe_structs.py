#!/usr/bin/env python3
"""Structures of a PE file

Documentation:
* https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
"""
import binascii
import contextlib
import ctypes
import datetime
import enum
import hashlib
import logging
from pathlib import Path
import re
import struct
import sys
import uuid


sys.path.insert(0, Path(__file__).parent)
from version_info import VsVersionInfo  # noqa


MICROSOFT_SYMBOLS_URL = 'https://msdl.microsoft.com/download/symbols'


# pylint: disable=invalid-name
logger = logging.getLogger(__name__)


@enum.unique
class MachineType(enum.IntEnum):
    """Type of machine in the COFF header"""
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_ARM = 0x1c0
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64
    IMAGE_FILE_MACHINE_ARMNT = 0x1c4
    IMAGE_FILE_MACHINE_I386 = 0x14c
    IMAGE_FILE_MACHINE_IA64 = 0x200
    IMAGE_FILE_MACHINE_THUMB = 0x1c2

    # For .NET Core
    IMAGE_FILE_MACHINE_NATIVE_OS_OVERRIDE_APPLE = 0x4644
    IMAGE_FILE_MACHINE_NATIVE_OS_OVERRIDE_FREEBSD = 0xadc4
    IMAGE_FILE_MACHINE_NATIVE_OS_OVERRIDE_LINUX = 0x7b79
    IMAGE_FILE_MACHINE_NATIVE_OS_OVERRIDE_NETBSD = 0x1993

    IMAGE_FILE_MACHINE_AMD64_LINUX_NI = 0xfd1d  # 0x7b79 ^ 0x8664


MACHINE_TYPE_NAME = {
    MachineType.IMAGE_FILE_MACHINE_AMD64: 'x86_64',
    MachineType.IMAGE_FILE_MACHINE_ARM: 'arm',  # ARM Little-Endian
    MachineType.IMAGE_FILE_MACHINE_ARM64: 'arm64',
    MachineType.IMAGE_FILE_MACHINE_ARMNT: 'armt2',  # ARM Thumb-2 Little-Endian
    MachineType.IMAGE_FILE_MACHINE_I386: 'x86',
    MachineType.IMAGE_FILE_MACHINE_IA64: 'ia64',  # Intel Itanium
    MachineType.IMAGE_FILE_MACHINE_THUMB: 'armt',  # ARM Thumb/Thumb-2 Little-Endian

    MachineType.IMAGE_FILE_MACHINE_AMD64_LINUX_NI: 'x86_64_Linux_NetCore',
}


@enum.unique
class ImageDirectoryEntry(enum.IntEnum):
    """Entries in optional header data directory"""
    IMAGE_DIRECTORY_ENTRY_EXPORT = 0  # Export Table (.edata)
    IMAGE_DIRECTORY_ENTRY_IMPORT = 1  # Import Table (.idata)
    IMAGE_DIRECTORY_ENTRY_RESOURCE = 2  # Resource Table (.rsrc)
    IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3  # Exception Table (.pdata)
    IMAGE_DIRECTORY_ENTRY_SECURITY = 4  # Attribute Certificate Table
    IMAGE_DIRECTORY_ENTRY_BASERELOC = 5  # Base Relocation Table
    IMAGE_DIRECTORY_ENTRY_DEBUG = 6  # Debug
    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7  # (Reserved, must be 0)
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8  # Global Pointer register value
    IMAGE_DIRECTORY_ENTRY_TLS = 9  # Thread Local Storage (TLS) Table
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10  # Load Config Table
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11  # Bound Import
    IMAGE_DIRECTORY_ENTRY_IAT = 12  # Import Address Table
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13  # Delay Import Descriptor
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14  # CLR Runtime Header


@enum.unique
class SectionFlags(enum.IntFlag):
    """Section Characteristics"""
    IMAGE_SCN_TYPE_NO_PAD = 0x00000008  # (obsolete, replaced by IMAGE_SCN_ALIGN_1BYTES)
    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_LNK_OTHER = 0x00000100
    IMAGE_SCN_LNK_INFO = 0x00000200
    IMAGE_SCN_LNK_REMOVE = 0x00000800
    IMAGE_SCN_LNK_COMDAT = 0x00001000
    IMAGE_SCN_GPREL = 0x00008000
    IMAGE_SCN_MEM_PURGEABLE = 0x00020000
    IMAGE_SCN_MEM_LOCKED = 0x00040000
    IMAGE_SCN_MEM_PRELOAD = 0x00080000
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
    IMAGE_SCN_MEM_SHARED = 0x10000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000


@enum.unique
class ResourceType(enum.IntEnum):
    """Resource types"""
    RT_CURSOR = 1
    RT_BITMAP = 2
    RT_ICON = 3
    RT_MENU = 4
    RT_DIALOG = 5
    RT_STRING = 6
    RT_FONTDIR = 7
    RT_FONT = 8
    RT_ACCELERATOR = 9  # Accelerator table.
    RT_RCDATA = 10  # Application-defined resource (raw data)
    RT_MESSAGETABLE = 11
    RT_GROUP_CURSOR = 12  # Hardware-independent cursor resource
    RT_GROUP_ICON = 14  # Hardware-independent icon resource
    RT_VERSION = 16
    RT_DLGINCLUDE = 17
    RT_PLUGPLAY = 19  # Plug and Play resource.
    RT_VXD = 20  # Virtual Device
    RT_ANICURSOR = 21  # Animated cursor
    RT_ANIICON = 22  # Animated icon
    RT_HTML = 23
    RT_MANIFEST = 24  # Side-by-Side Assembly Manifest


class struct_image_dos_header(ctypes.Structure):
    """IMAGE_DOS_HEADER"""
    _fields_ = [
        ('e_magic', ctypes.c_uint16),
        ('e_cblp', ctypes.c_uint16),
        ('e_cp', ctypes.c_uint16),
        ('e_crlc', ctypes.c_uint16),
        ('e_cparhdr', ctypes.c_uint16),
        ('e_minalloc', ctypes.c_uint16),
        ('e_maxalloc', ctypes.c_uint16),
        ('e_ss', ctypes.c_uint16),
        ('e_sp', ctypes.c_uint16),
        ('e_csum', ctypes.c_uint16),
        ('e_ip', ctypes.c_uint16),
        ('e_cs', ctypes.c_uint16),
        ('e_lfarlc', ctypes.c_uint16),
        ('e_ovno', ctypes.c_uint16),
        ('e_res', ctypes.c_uint16 * 4),
        ('e_oemid', ctypes.c_uint16),
        ('e_oeminfo', ctypes.c_uint16),
        ('e_res2', ctypes.c_uint16 * 10),
        ('e_lfanew', ctypes.c_uint32),
    ]


assert ctypes.sizeof(struct_image_dos_header) == 0x40


class struct_image_file_header(ctypes.Structure):
    """IMAGE_FILE_HEADER (COFF Header)"""
    _fields_ = [
        ('Machine', ctypes.c_uint16),
        ('NumberOfSections', ctypes.c_uint16),
        ('TimeDateStamp', ctypes.c_uint32),
        ('PointerToSymbolTable', ctypes.c_uint32),
        ('NumberOfSymbols', ctypes.c_uint32),
        ('SizeOfOptionalHeader', ctypes.c_uint16),
        ('Characteristics', ctypes.c_uint16),
    ]


assert ctypes.sizeof(struct_image_file_header) == 0x14


class struct_image_data_directory(ctypes.Structure):
    """IMAGE_DATA_DIRECTORY"""
    _fields_ = [
        ('VirtualAddress', ctypes.c_uint32),
        ('Size', ctypes.c_uint32),
    ]

    def is_empty(self):
        return self.VirtualAddress == 0 and self.Size == 0


assert ctypes.sizeof(struct_image_data_directory) == 8


class struct_image_optional_header32(ctypes.Structure):
    """IMAGE_OPTIONAL_HEADER (PE32 format, 32 bits)"""
    _fields_ = [
        ('Magic', ctypes.c_uint16),
        ('MajorLinkerVersion', ctypes.c_uint8),
        ('MinorLinkerVersion', ctypes.c_uint8),
        ('SizeOfCode', ctypes.c_uint32),
        ('SizeOfInitializedData', ctypes.c_uint32),
        ('SizeOfUninitializedData', ctypes.c_uint32),
        ('AddressOfEntryPoint', ctypes.c_uint32),
        ('BaseOfCode', ctypes.c_uint32),
        ('BaseOfData', ctypes.c_uint32),
        ('ImageBase', ctypes.c_uint32),
        ('SectionAlignment', ctypes.c_uint32),
        ('FileAlignment', ctypes.c_uint32),
        ('MajorOperatingSystemVersion', ctypes.c_uint16),
        ('MinorOperatingSystemVersion', ctypes.c_uint16),
        ('MajorImageVersion', ctypes.c_uint16),
        ('MinorImageVersion', ctypes.c_uint16),
        ('MajorSubsystemVersion', ctypes.c_uint16),
        ('MinorSubsystemVersion', ctypes.c_uint16),
        ('Win32VersionValue', ctypes.c_uint32),
        ('SizeOfImage', ctypes.c_uint32),
        ('SizeOfHeaders', ctypes.c_uint32),
        ('CheckSum', ctypes.c_uint32),
        ('Subsystem', ctypes.c_uint16),
        ('DllCharacteristics', ctypes.c_uint16),
        ('SizeOfStackReserve', ctypes.c_uint32),
        ('SizeOfStackCommit', ctypes.c_uint32),
        ('SizeOfHeapReserve', ctypes.c_uint32),
        ('SizeOfHeapCommit', ctypes.c_uint32),
        ('LoaderFlags', ctypes.c_uint32),
        ('NumberOfRvaAndSizes', ctypes.c_uint32),
        ('DataDirectory', struct_image_data_directory * 16),
    ]


assert ctypes.sizeof(struct_image_optional_header32) == 0xe0


class struct_image_optional_header64(ctypes.Structure):
    """IMAGE_OPTIONAL_HEADER64 (PE32+ format, 64 buts)"""
    _fields_ = [
        ('Magic', ctypes.c_uint16),
        ('MajorLinkerVersion', ctypes.c_uint8),
        ('MinorLinkerVersion', ctypes.c_uint8),
        ('SizeOfCode', ctypes.c_uint32),
        ('SizeOfInitializedData', ctypes.c_uint32),
        ('SizeOfUninitializedData', ctypes.c_uint32),
        ('AddressOfEntryPoint', ctypes.c_uint32),
        ('BaseOfCode', ctypes.c_uint32),
        ('ImageBase', ctypes.c_uint64),
        ('SectionAlignment', ctypes.c_uint32),
        ('FileAlignment', ctypes.c_uint32),
        ('MajorOperatingSystemVersion', ctypes.c_uint16),
        ('MinorOperatingSystemVersion', ctypes.c_uint16),
        ('MajorImageVersion', ctypes.c_uint16),
        ('MinorImageVersion', ctypes.c_uint16),
        ('MajorSubsystemVersion', ctypes.c_uint16),
        ('MinorSubsystemVersion', ctypes.c_uint16),
        ('Win32VersionValue', ctypes.c_uint32),
        ('SizeOfImage', ctypes.c_uint32),
        ('SizeOfHeaders', ctypes.c_uint32),
        ('CheckSum', ctypes.c_uint32),
        ('Subsystem', ctypes.c_uint16),
        ('DllCharacteristics', ctypes.c_uint16),
        ('SizeOfStackReserve', ctypes.c_uint64),
        ('SizeOfStackCommit', ctypes.c_uint64),
        ('SizeOfHeapReserve', ctypes.c_uint64),
        ('SizeOfHeapCommit', ctypes.c_uint64),
        ('LoaderFlags', ctypes.c_uint32),
        ('NumberOfRvaAndSizes', ctypes.c_uint32),
        ('DataDirectory', struct_image_data_directory * 16),
    ]


assert ctypes.sizeof(struct_image_optional_header64) == 0xf0


class struct_image_nt_header32(ctypes.Structure):
    """IMAGE_NT_HEADER (32 bits)"""
    _fields_ = [
        ('Signature', ctypes.c_uint32),
        ('FileHeader', struct_image_file_header),
        ('OptionalHeader', struct_image_optional_header32),
    ]


assert ctypes.sizeof(struct_image_nt_header32) == 0xf8


class struct_image_nt_header64(ctypes.Structure):
    """IMAGE_NT_HEADER64"""
    _fields_ = [
        ('Signature', ctypes.c_uint32),
        ('FileHeader', struct_image_file_header),
        ('OptionalHeader', struct_image_optional_header64),
    ]


assert ctypes.sizeof(struct_image_nt_header64) == 0x108


class struct_image_section_header(ctypes.Structure):
    """IMAGE_SECTION_HEADER"""
    _fields_ = [
        ('Name', ctypes.c_char * 8),
        ('VirtualSize', ctypes.c_uint32),
        ('VirtualAddress', ctypes.c_uint32),
        ('SizeOfRawData', ctypes.c_uint32),
        ('PointerToRawData', ctypes.c_uint32),
        ('PointerToRelocations', ctypes.c_uint32),
        ('PointerToLinenumbers', ctypes.c_uint32),
        ('NumberOfRelocations', ctypes.c_uint16),
        ('NumberOfLinenumbers', ctypes.c_uint16),
        ('Characteristics', ctypes.c_uint32),
    ]


assert ctypes.sizeof(struct_image_section_header) == 0x28


class struct_image_export_directory(ctypes.Structure):
    """IMAGE_EXPORT_DIRECTORY"""
    _fields_ = [
        ('Characteristics', ctypes.c_uint32),
        ('TimeDateStamp', ctypes.c_uint32),
        ('MajorVersion', ctypes.c_uint16),
        ('MinorVersion', ctypes.c_uint16),
        ('Name', ctypes.c_uint32),
        ('Base', ctypes.c_uint32),
        ('NumberOfFunctions', ctypes.c_uint32),
        ('NumberOfNames', ctypes.c_uint32),
        ('AddressOfFunctions', ctypes.c_uint32),
        ('AddressOfNames', ctypes.c_uint32),
        ('AddressOfNameOrdinals', ctypes.c_uint32),
    ]


assert ctypes.sizeof(struct_image_export_directory) == 0x28


class struct_image_resource_directory(ctypes.Structure):
    """IMAGE_RESOURCE_DIRECTORY"""
    _fields_ = [
        ('Characteristics', ctypes.c_uint32),
        ('TimeDateStamp', ctypes.c_uint32),
        ('MajorVersion', ctypes.c_uint16),
        ('MinorVersion', ctypes.c_uint16),
        ('NumberOfNamedEntries', ctypes.c_uint16),
        ('NumberOfIdEntries', ctypes.c_uint16),
    ]


assert ctypes.sizeof(struct_image_resource_directory) == 0x10


class struct_image_resource_data_entry(ctypes.Structure):
    """IMAGE_RESOURCE_DATA_ENTRY"""
    _fields_ = [
        ('OffsetToData', ctypes.c_uint32),
        ('Size', ctypes.c_uint32),
        ('CodePage', ctypes.c_uint32),
        ('Reserved', ctypes.c_uint32),
    ]


assert ctypes.sizeof(struct_image_resource_data_entry) == 0x10


class struct_image_debug_directory(ctypes.Structure):
    """IMAGE_DEBUG_DIRECTORY"""
    _fields_ = [
        ('Characteristics', ctypes.c_uint32),
        ('TimeDateStamp', ctypes.c_uint32),
        ('MajorVersion', ctypes.c_uint16),
        ('MinorVersion', ctypes.c_uint16),
        ('Type', ctypes.c_uint32),
        ('SizeOfData', ctypes.c_uint32),
        ('AddressOfRawData', ctypes.c_uint32),
        ('PointerToRawData', ctypes.c_uint32),
    ]


assert ctypes.sizeof(struct_image_debug_directory) == 0x1c


def format_int(value: int) -> str:
    """Format an integer, maybe using hexadecimal"""
    return str(value) if 0 <= value < 10 else hex(value)


def dump_array_struct(array, indent='', key=None):
    """Dump the fields of a ctypes array of structures"""
    if key == 'DataDirectory':
        idx_names = {x.value: x.name for x in ImageDirectoryEntry}
    else:
        idx_names = {}

    for idx, value in enumerate(array):
        if hasattr(value, 'is_empty') and value.is_empty():
            # Skip empty items
            continue

        try:
            print("{}[{} = {}]:".format(indent, idx, idx_names[idx]))
        except KeyError:
            print("{}[{}]:".format(indent, idx))
        dump_struct(value, indent=indent + '  ')


def dump_struct(obj, indent=''):
    """Dump the fields of a ctypes structure"""
    for key, field_type in obj._fields_:
        value = getattr(obj, key)

        if isinstance(value, int):
            repr_value = format_int(value)
            if key == 'TimeDateStamp' and value != 0:
                # Add the decoded timestamp, from 1970-01-01 00:00:00
                # NB: since Windows 10, Microsoft uses reproducible builds that randomize the timestamp:
                # https://devblogs.microsoft.com/oldnewthing/?p=97705
                repr_value += " ({})".format(datetime.datetime.utcfromtimestamp(value))
            elif key == 'Machine' and value != 0:
                with contextlib.suppress(ValueError):
                    repr_value += " ({} = {})".format(MachineType(value).name, MACHINE_TYPE_NAME.get(value))
            elif isinstance(obj, struct_image_section_header) and key == 'Characteristics' and value != 0:
                remaining = value
                flags = []
                for sect_flag in SectionFlags:
                    if remaining & sect_flag.value:
                        flags.append(sect_flag.name)
                        remaining &= ~sect_flag.value
                if remaining:
                    flags.append(hex(remaining))
                repr_value += " ({})".format('|'.join(flags))
            print("{}* {} = {}".format(indent, key, repr_value))
        elif isinstance(value, ctypes.Structure):
            print("{}* {}:".format(indent, key))
            dump_struct(value, indent=indent + '  ')
        elif isinstance(value, ctypes.Array):
            assert field_type._length_ > 0
            first = value[0]
            if isinstance(first, int):
                print("{}* {} = [{}]".format(
                    indent, key,
                    ', '.join(format_int(x) for x in value)))
            elif isinstance(first, ctypes.Structure):
                print("{}* {}:".format(indent, key))
                dump_array_struct(value, indent=indent + '  ', key=key)
            else:
                raise NotImplementedError("Unable to represent array of {} for key {}".format(
                    field_type._type_, key))
        else:
            print("{}* {} = {}".format(indent, key, repr(value)))


def dump_dict(obj, indent=''):
    """Dump the fields of a dictionary"""
    for key, value in obj.items():
        if isinstance(value, int):
            print("{}* {} = {}".format(indent, key, format_int(value)))
        elif isinstance(value, dict):
            print("{}* {}:".format(indent, key))
            dump_dict(value, indent=indent + '  ')
        else:
            print("{}* {} = {}".format(indent, key, repr(value)))


class PEFile:
    """Loaded PE (Portable Executable) file"""
    def __init__(self, file_path: Path):
        # Read the whole file into memory
        with file_path.open('rb') as stream:
            content = stream.read()
        self.file_content = content

        # Parse the MZDOS header
        if content[:2] != b'MZ':  # IMAGE_DOS_SIGNATURE
            raise ValueError("Invalid MZ magic in {}: {}".format(file_path, repr(content[:2])))
        self.mzdos_header = struct_image_dos_header.from_buffer_copy(content)

        peheader_offset = self.mzdos_header.e_lfanew
        if content[peheader_offset:peheader_offset + 4] != b'PE\0\0':  # IMAGE_NT_SIGNATURE
            raise ValueError("Invalid PE magic in {}: {}".format(
                file_path, repr(content[peheader_offset:peheader_offset + 4])))

        # Find the optional header magic to differentiate between 32 and 64 bits
        pe_optional_offset = peheader_offset + 0x18
        opt_header_magic = content[pe_optional_offset:pe_optional_offset + 2]
        if opt_header_magic == b'\x0b\x01':  # IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
            self.pe_header = struct_image_nt_header32.from_buffer_copy(content, peheader_offset)
            if self.pe_header.FileHeader.SizeOfOptionalHeader != 0xe0:
                raise ValueError("Unexpected SizeOfOptionalHeader in {}: {:#x} != 0xe0".format(
                    file_path, self.pe_header.FileHeader.SizeOfOptionalHeader))
        elif opt_header_magic == b'\x0b\x02':  # IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
            self.pe_header = struct_image_nt_header64.from_buffer_copy(content, peheader_offset)
            if self.pe_header.FileHeader.SizeOfOptionalHeader != 0xf0:
                raise ValueError("Unexpected SizeOfOptionalHeader in {}: {:#x} != 0xf0".format(
                    file_path, self.pe_header.FileHeader.SizeOfOptionalHeader))
        else:
            raise ValueError("Invalid PE optional header magic in {}: {}".format(file_path, repr(opt_header_magic)))

        if self.pe_header.OptionalHeader.NumberOfRvaAndSizes != 0x10:
            raise NotImplementedError("Unexpected NumberOfRvaAndSizes in {}: {:#x} != 0x10".format(
                file_path, self.pe_header.OptionalHeader.NumberOfRvaAndSizes))

        # List the regions that are excluded from authenticode hashing
        # cf. https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx
        self.authenticode_excluded = [
            # Exclude CheckSum field from Authenticode signature
            (pe_optional_offset + 0x40, 4),
            # Exclude the entry of the Attribute Certificate Table in the Data Directory
            (
                pe_optional_offset + self.pe_header.FileHeader.SizeOfOptionalHeader -
                8 * self.pe_header.OptionalHeader.NumberOfRvaAndSizes +
                8 * ImageDirectoryEntry.IMAGE_DIRECTORY_ENTRY_SECURITY, 8),
        ]
        # Exclude the Attribute Certificate Table
        entry = self.pe_header.OptionalHeader.DataDirectory[ImageDirectoryEntry.IMAGE_DIRECTORY_ENTRY_SECURITY]
        if entry.Size != 0:
            self.authenticode_excluded.append((entry.VirtualAddress, entry.Size))
        self.authenticode_excluded.sort()

        self.authenticode_file_end = 0

        # Read the section headers
        section_header_offset = pe_optional_offset + self.pe_header.FileHeader.SizeOfOptionalHeader
        section_headers_type = struct_image_section_header * self.pe_header.FileHeader.NumberOfSections
        self.section_headers = section_headers_type.from_buffer_copy(content, section_header_offset)

        # Load all sections as (start, end, content, name) tuples
        sections = []
        for idx, sect_header in enumerate(self.section_headers):
            sect_virt_addr = sect_header.VirtualAddress
            sect_virt_size = sect_header.VirtualSize
            sect_offset = sect_header.PointerToRawData
            sect_raw_size = sect_header.SizeOfRawData
            sect_raw_end = sect_offset + sect_raw_size

            # On old programs, the virtual size of the section may be empty while the file contains data
            if sect_virt_size == 0 and sect_raw_size > 0:
                logger.warning("Section %d (%r) is virtually empty but holds %#x bytes in file, loading it anyway",
                               idx, sect_header.Name, sect_raw_size)
                sect_virt_size = sect_raw_size

            if sect_virt_size == 0:
                raise ValueError("Section {} of {} is virtually empty".format(idx, file_path))

            if sect_offset > len(content):
                raise ValueError("Section {} of {} starts out of file bounds".format(idx, file_path))
            if sect_raw_end > len(content):
                raise ValueError("Section {} of {} ends out of file bounds".format(idx, file_path))
            sect_content = content[sect_offset:sect_raw_end]
            assert len(sect_content) == sect_raw_size
            if sect_virt_size < sect_raw_size:
                # Truncate the section, which was aligned in the file
                sect_content = sect_content[:sect_virt_size]
            elif sect_virt_size > sect_raw_size:
                # Expand the section, which contains zeros
                sect_content += b'\0' * (sect_virt_size - sect_raw_size)
            assert len(sect_content) == sect_virt_size

            sect_name = sect_header.Name.decode('ascii')
            sections.append((sect_virt_addr, sect_virt_addr + sect_virt_size, sect_content, sect_name))

            # Compute the end of file from the point of view of authenticode
            if sect_raw_end > self.authenticode_file_end:
                self.authenticode_file_end = sect_raw_end

        # Sort the sections and ensure they are not overlapping
        sections.sort()
        for idx in range(len(sections) - 1):
            if sections[idx][1] > sections[idx + 1][0]:
                raise ValueError(
                    "PE file {0} contains overlapping sections {1[0]:#x}-{1[1]:#x} and {2[0]:#x}-{2[1]:#x}".format(
                        file_path, sections[idx], sections[idx + 1]))
        self.sections = sections

        self.export_directory = None
        self.export_dll_name = None
        self.exported_functions = None
        self.exported_functions_ord = None
        self.load_export_table()

        self.resources = None
        self.resource_version_info = None
        self.load_resource_directory()

        self.signatures = None
        self.load_attribute_certificate_table()

        self.debug_directories = None
        self.debug_data = None
        self.debug_codeview_guid = None
        self.debug_codeview_timestamp = None
        self.debug_codeview_age = None
        self.debug_codeview_path = None
        self.debug_repro_data = None
        self.debug_repro_size = None
        self.debug_repro_guid = None
        self.debug_repro_unknown = None
        self.debug_repro_timestamp = None
        self.load_debug_directory()

        self.syscall_stubs = None
        self.enumerate_syscall_stubs()

        # Find out the PE file name from the information
        self.pe_file_name = None
        if self.resource_version_info and self.resource_version_info.original_file_name:
            # Ensure that the file has a valid extension
            # This fails for example with C:/Windows/System32/activeds.dll, which has "ADs"
            if self.resource_version_info.original_file_name.upper().endswith(('.DLL', '.EXE', '.SYS')) and \
                    self.resource_version_info.original_file_name.upper() != '*.EXE':
                self.pe_file_name = self.resource_version_info.original_file_name

        if not self.pe_file_name and self.export_dll_name:
            # Use the exported DLL name, if it ends with .DLL or .EXE
            if self.export_dll_name.upper().endswith(('.DLL', '.EXE')):
                self.pe_file_name = self.export_dll_name

        if self.pe_file_name:
            if not re.match(r'^[-0-9A-Za-z._+ ]+\.(DLL|Dll|EXE|Exe|SYS|Sys|dll|exe|sys)$', self.pe_file_name):
                logger.warning("Unexpected characters or pattern in computed PE file name: %r", self.pe_file_name)
                self.pe_file_name = None

    def get_section_name(self, addr: int) -> str:
        """Get the name of a section containing the given address"""
        for sect_start, sect_end, _sect_content, sect_name in self.sections:
            if sect_start <= addr < sect_end:
                return sect_name
        raise ValueError("Unable to find address {:#x} in sections".format(addr))

    def get_virtual(self, addr: int, size: int) -> bytes:
        """Get bytes at the given Relative Virtual Address (RVA)"""
        if addr == 0:
            raise ValueError("Unable to get {:#x} bytes from NULL".format(size))
        for sect_start, sect_end, sect_content, _sect_name in self.sections:
            if sect_start <= addr < sect_end:
                if addr + size > sect_end:
                    raise ValueError("Chunk {:#x}..{:#x} goes past the section".format(addr, addr + size))
                offset = addr - sect_start
                assert offset >= 0
                assert offset + size <= len(sect_content)
                return sect_content[offset:offset + size]
        raise ValueError("Unable to find address {:#x} in sections".format(addr))

    def get_virtual_asz(self, addr: int) -> str:
        """Get an ANSI string located at the given Relative Virtual Address (RVA)"""
        if addr == 0:
            raise ValueError("Unable to get an ASCII string from NULL")
        for sect_start, sect_end, sect_content, _sect_name in self.sections:
            if sect_start <= addr < sect_end:
                offset = addr - sect_start
                zero_off = sect_content.index(b'\0', offset)
                asz_bytes = sect_content[offset:zero_off]
                return asz_bytes.decode('ascii')
        raise ValueError("Unable to find address {:#x} in sections".format(addr))

    def load_export_table(self):
        """Load the export table"""
        # Get the export table entry in the optional header data directory
        entry = self.pe_header.OptionalHeader.DataDirectory[ImageDirectoryEntry.IMAGE_DIRECTORY_ENTRY_EXPORT]
        if entry.Size == 0:
            return

        # Parse the Export Directory Table
        self.export_directory = struct_image_export_directory.from_buffer_copy(
            self.get_virtual(entry.VirtualAddress, entry.Size))
        if self.export_directory.Name:
            self.export_dll_name = self.get_virtual_asz(self.export_directory.Name)

        # Load function names and ordinals
        ordinal_base = self.export_directory.Base
        num_funcs = self.export_directory.NumberOfFunctions
        num_names = self.export_directory.NumberOfNames
        if num_funcs == 0:
            return

        function_addresses = struct.unpack(
            '<{}I'.format(num_funcs),
            self.get_virtual(self.export_directory.AddressOfFunctions, num_funcs * 4))

        # Find forwarder RVA entries in the functions
        export_section_start = entry.VirtualAddress
        export_section_end = entry.VirtualAddress + entry.Size
        function_addresses = list(function_addresses)
        for fct_idx, export_rva in enumerate(function_addresses):
            if export_section_start <= export_rva < export_section_end:
                forwarder_name = self.get_virtual_asz(export_rva)
                function_addresses[fct_idx] = forwarder_name

        # Find missing unbiased ordinals (i.e. ordinals without the ordinal base)
        self.exported_functions = {}
        self.exported_functions_ord = {}
        missing_unbiased_ord = set(range(num_funcs))

        # An export table might have no name
        if num_names:
            name_addresses = struct.unpack(
                '<{}I'.format(num_names),
                self.get_virtual(self.export_directory.AddressOfNames, num_names * 4))
            name2ord_addresses = struct.unpack(
                '<{}H'.format(num_names),
                self.get_virtual(self.export_directory.AddressOfNameOrdinals, num_names * 2))
            for name_rva, name_unbiased_ord in zip(name_addresses, name2ord_addresses):
                name = self.get_virtual_asz(name_rva)
                func_addr = function_addresses[name_unbiased_ord]
                if name in self.exported_functions:
                    if self.exported_functions[name] != func_addr:
                        raise ValueError("Function {} is exported several times: {} and {}".format(
                            repr(name), repr(self.exported_functions[name]), repr(func_addr)))
                else:
                    self.exported_functions[name] = func_addr
                    self.exported_functions_ord[name] = ordinal_base + name_unbiased_ord
                missing_unbiased_ord.remove(name_unbiased_ord)

        if missing_unbiased_ord:
            # Export functions with faked name
            for name_unbiased_ord in missing_unbiased_ord:
                func_addr = function_addresses[name_unbiased_ord]
                if func_addr == 0:
                    # Ignore exported NULL addresses with no name
                    continue
                name = "#{}".format(ordinal_base + name_unbiased_ord)
                if name in self.exported_functions:
                    raise ValueError("Function {} is exported several times".format(repr(name)))
                self.exported_functions[name] = func_addr
                self.exported_functions_ord[name] = ordinal_base + name_unbiased_ord

    def load_resource_directory(self):
        """Load the resource directory table"""
        entry = self.pe_header.OptionalHeader.DataDirectory[ImageDirectoryEntry.IMAGE_DIRECTORY_ENTRY_RESOURCE]
        if entry.Size == 0:
            return

        # Load the content, which is used by offsets
        content = self.get_virtual(entry.VirtualAddress, entry.Size)

        def get_unicode_string(offset: int) -> str:
            length, = struct.unpack('<H', content[offset:offset + 2])
            return content[offset + 2:offset + 2 + 2 * length].decode('utf-16le')

        # The resource directory is a header for a table for name entries and ID entries.
        resources_offsets = []

        # The structure is recursive: use a stack of (offset to directory, path) to load it.
        stack = [(0, [])]
        while stack:
            offset, res_path = stack.pop()
            resource_dir = struct_image_resource_directory.from_buffer_copy(content, offset)
            offset += 0x10
            subdirectories = []
            for _ in range(resource_dir.NumberOfNamedEntries):
                # Load a name entry
                name_offset, data_offset = struct.unpack('<II', content[offset:offset + 8])
                offset += 8
                if not name_offset & 0x80000000:  # IMAGE_RESOURCE_NAME_IS_STRING
                    raise ValueError("Unexpected integer ID {:#x} in resource named entry".format(name_offset))
                item_path = res_path + [get_unicode_string(name_offset & ~0x80000000)]
                if data_offset & 0x80000000:  # IMAGE_RESOURCE_DATA_IS_DIRECTORY
                    subdirectories.append((data_offset & ~0x80000000, item_path))
                else:
                    resources_offsets.append((data_offset, item_path))

            for _ in range(resource_dir.NumberOfIdEntries):
                # Load an ID entry
                name_offset, data_offset = struct.unpack('<II', content[offset:offset + 8])
                offset += 8
                if name_offset & 0x80000000:  # IMAGE_RESOURCE_NAME_IS_STRING
                    raise ValueError("Unexpected string name {:#x} in resource ID entry".format(name_offset))
                item_path = res_path + [name_offset]
                if data_offset & 0x80000000:  # IMAGE_RESOURCE_DATA_IS_DIRECTORY
                    subdirectories.append((data_offset & ~0x80000000, item_path))
                else:
                    resources_offsets.append((data_offset, item_path))

            # Dequeue the subdirectories in the same order they were seen
            stack += subdirectories[::-1]

        res_type_names = {x.value: x.name for x in ResourceType}

        # Now browse the resources
        self.resources = []
        for res_offset, res_path in resources_offsets:
            res_entry = struct_image_resource_data_entry.from_buffer_copy(content, res_offset)
            if res_entry.Size == 0:
                res_data = b''
            else:
                res_data = self.get_virtual(res_entry.OffsetToData, res_entry.Size)

            if len(res_path) != 3:
                raise NotImplementedError("Resource path does not follow Type/Name/Language levels: {}".format(
                    repr(res_path)))

            # Reformat the resource path in a more readable way
            p_type, p_name, p_lang = res_path

            if p_type == ResourceType.RT_VERSION and p_name == 1:
                self.resource_version_info = VsVersionInfo(res_data)

            if p_type in res_type_names:
                p_type = res_type_names[p_type]

            if not isinstance(p_lang, int):
                raise NotImplementedError("Resource path does not have an integer language: {}".format(
                    repr(res_path)))

            if p_lang == 1033:
                p_lang = 'en_US'

            res_path = '{}/{}/{}'.format(p_type, p_name, p_lang)
            self.resources.append((res_path, res_data, res_entry.CodePage))

    def load_attribute_certificate_table(self):
        """Load the attribute certificate table"""
        entry = self.pe_header.OptionalHeader.DataDirectory[ImageDirectoryEntry.IMAGE_DIRECTORY_ENTRY_SECURITY]
        if entry.Size == 0:
            return

        # Use the file content (it is a Physical Address!)
        content = self.file_content[entry.VirtualAddress:entry.VirtualAddress + entry.Size]

        # Sometimes, it is empty but has many zeros
        if all(x == 0 for x in content):
            return

        # Load a table of structures WIN_CERTIFICATE:
        #     DWORD dwLength;
        #     WORD wRevision;
        #     WORD wCertificateType;
        #     BYTE bCertificate[ANYSIZE_ARRAY];
        self.signatures = []
        offset = 0
        while offset < len(content):
            length, rev, cert_type = struct.unpack('<IHH', content[offset:offset + 8])
            if length < 8 or offset + length > len(content):
                raise ValueError("Invalid attribute certificate table length: {:#x}".format(length))
            cert_content = content[offset + 8:offset + length]
            offset += length

            if rev == 0x100:  # WIN_CERT_REVISION_1_0
                if len(cert_content) == 0x80:
                    # Observed files (from Windows XP) always have 128 bytes of data
                    logger.warning("Version 1 Win_Certificate structure is not implemented")
                else:
                    raise NotImplementedError("Version 1 Win_Certificate structure is not implemented")
            elif rev == 0x200:  # WIN_CERT_REVISION_2_0
                if cert_type == 2:  # WIN_CERT_TYPE_PKCS_SIGNED_DATA
                    self.signatures.append(cert_content)
                else:
                    raise ValueError("Unexpected Win_Certificate.cert_type value: {:#x}".format(rev))
            else:
                raise ValueError("Unexpected Win_Certificate.rev value: {:#x}".format(rev))

    def compute_authenticode_digest(self, algorithm):
        """Compute the authenticode digest of the PE file"""
        engine = hashlib.new(algorithm)
        current_offset = 0
        for start, size in self.authenticode_excluded:
            engine.update(self.file_content[current_offset:start])
            current_offset = start + size
        if current_offset < self.authenticode_file_end:
            engine.update(self.file_content[current_offset:self.authenticode_file_end])
        return engine.digest()

    def load_debug_directory(self):
        """Load the debug directory"""
        entry = self.pe_header.OptionalHeader.DataDirectory[ImageDirectoryEntry.IMAGE_DIRECTORY_ENTRY_DEBUG]
        if entry.Size == 0:
            return
        if entry.Size % 0x1c:
            raise ValueError("Unexpected size of debug directory: {:#x} not a multiple of 0x1c".format(entry.Size))
        entry_count = entry.Size // 0x1c
        debug_directory_type = struct_image_debug_directory * entry_count
        self.debug_directories = debug_directory_type.from_buffer_copy(
            self.get_virtual(entry.VirtualAddress, entry.Size))

        self.debug_data = [None] * entry_count
        for idx, debug_directory in enumerate(self.debug_directories):
            # Ensure that AddressOfRawData is the RVA of PointerToRawData
            data_file_addr = debug_directory.PointerToRawData
            data_size = debug_directory.SizeOfData
            if data_size == 0:
                if debug_directory.Type == 0x10:  # IMAGE_DEBUG_TYPE_REPRO, with no data
                    self.debug_repro_data = b''
                continue
            if data_file_addr == 0:
                raise ValueError("Debug Directory has PointerToRawData = 0")

            debug_data = None
            if debug_directory.AddressOfRawData != 0:
                for sect_header in self.section_headers:
                    sect_virt_addr = sect_header.VirtualAddress
                    sect_virt_size = sect_header.VirtualSize
                    sect_virt_end = sect_virt_addr + sect_virt_size
                    if sect_virt_addr <= debug_directory.AddressOfRawData < sect_virt_end:
                        sect_raw_addr = sect_header.PointerToRawData
                        sect_raw_size = sect_header.SizeOfRawData
                        sect_raw_end = sect_raw_addr + sect_raw_size
                        if not sect_raw_addr <= debug_directory.PointerToRawData < sect_raw_end:
                            raise ValueError("Mismatched AddressOfRawData/PointerToRawData in Debug Directory")
                        if debug_directory.AddressOfRawData + data_size > sect_virt_end:
                            raise ValueError("Data of Debug Directory overflows the virtual section")
                        if debug_directory.PointerToRawData + data_size > sect_raw_end:
                            raise ValueError("Data of Debug Directory overflows the file section")
                        debug_data = self.file_content[data_file_addr:data_file_addr + data_size]
                        break
            else:
                # There is only a pointer to data in the file
                debug_data = self.file_content[data_file_addr:data_file_addr + data_size]

            if debug_data is None:
                raise ValueError("Unable to find the debug AddressOfRawData in PE sections")
            self.debug_data[idx] = debug_data

            if debug_directory.Type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                if debug_data.startswith(b'RSDS'):  # PDB 7.0 files
                    self.debug_codeview_guid = uuid.UUID(bytes_le=debug_data[4:0x14])
                    self.debug_codeview_age, = struct.unpack('<I', debug_data[0x14:0x18])
                    self.debug_codeview_path = debug_data[0x18:].decode('utf-8').rstrip('\0')
                elif debug_data.startswith(b'NB10'):  # PDB 2.0 files
                    offset, timestamp, age = struct.unpack('<III', debug_data[0x4:0x10])
                    self.debug_codeview_timestamp = timestamp
                    self.debug_codeview_age = age
                    self.debug_codeview_path = debug_data[0x10:].decode('utf-8').rstrip('\0')
                elif debug_data.startswith(b'NB11'):  # CodeView 5.0
                    # Do not parse embedded debug data
                    pass
                elif debug_data.startswith(b'NB09'):  # CodeView 4.10
                    # Do not parse embedded debug data
                    pass
                else:
                    raise ValueError("Invalid Debug CODEVIEW magic: {}".format(repr(debug_data[:4])))

            if debug_directory.Type == 0x10:  # IMAGE_DEBUG_TYPE_REPRO (/Brepro linker option)
                # cf. https://blog.amossys.fr/pe-timestamps-and-bepro-flag.html
                self.debug_repro_data = debug_data
                # Try to decode the data
                if len(debug_data) != 0x24:
                    raise ValueError("Unexpected size of Reproducible Build Debug data: {:#x}".format(
                        len(debug_data)))
                self.debug_repro_size, = struct.unpack('<I', debug_data[:4])
                self.debug_repro_guid = uuid.UUID(bytes_le=debug_data[4:0x14])
                self.debug_repro_unknown = debug_data[0x14:0x20]
                self.debug_repro_timestamp, = struct.unpack('<I', debug_data[0x20:])

        # Check that the data is coherent
        if self.debug_repro_data:
            if self.debug_repro_size != 0x20:
                raise ValueError("Unexpected embedded size of Reproducible Build Debug data: {:#x}".format(
                    self.debug_repro_size))
            if self.debug_codeview_guid is not None and self.debug_repro_guid != self.debug_codeview_guid:
                raise ValueError("Mismatched Reproducible Build GUID: {} != {}".format(
                    self.debug_repro_guid, self.debug_codeview_guid))
            if self.debug_repro_timestamp != self.pe_header.FileHeader.TimeDateStamp:
                # This occcured for example with
                # C:/Windows/SoftwareDistribution/Download/Install/Windows-KB890830-x64-V5.75-delta.exe
                # because the debug timestamp is different from the PE Header one
                logger.warning("Mismatched Reproducible Build timestamp: %#x != %#x",
                               self.debug_repro_timestamp, self.pe_header.FileHeader.TimeDateStamp)

    def enumerate_syscall_stubs(self):
        """Find all syscall stubs

        Documentation:
        * http://codemachine.com/article_syscall.html
        * http://www.nynaeve.net/?p=48
        * https://shift32.wordpress.com/2011/10/14/inside-kisystemservice/
        * http://www.osronline.com/article.cfm%5earticle=257.htm
        * https://github.com/tinysec/windows-syscall-table
        * https://github.com/volatilityfoundation/volatility/tree/2.6.1/volatility/plugins/overlays/windows
          (with list of syscalls)
        """
        if not self.exported_functions:
            return
        syscall_stubs = {}
        for name, target in self.exported_functions.items():
            if isinstance(target, str):
                # Ignore forwarder exports
                continue
            assert isinstance(target, int)
            try:
                function_13bytes = self.get_virtual(target, 13)
            except ValueError:
                function_13bytes = b''
            try:
                function_24bytes = self.get_virtual(target, 24)
            except ValueError:
                function_24bytes = b''

            # 32-bit ntdll.dll on Windows 7 using _KUSER_SHARED_DATA!SystemCall (15 bytes)
            #   b8 42 00 00 00          mov    eax,0x42
            #   ba 00 03 fe 7f          mov    edx,0x7ffe0300
            #   ff 12                   call   DWORD PTR [edx]
            #   c2 2c 00                ret    0x2c     ; or something else
            if function_13bytes[:1] == b'\xb8' and \
                    function_13bytes[5:0xd] == b'\xba\x00\x03\xfe\x7f\xff\x12\xc2':
                sysnum, = struct.unpack('<I', function_13bytes[1:5])
                syscall_stubs[name] = sysnum

            # 32-bit ntdll.dll with possible WoW64 (15 bytes)
            #   b8 9a 00 00 00          mov    eax,0x9a
            #   ba 80 ca 2f 4b          mov    edx,0x4b2fca80
            #   ff d2                   call   edx
            #   c2 2c 00                ret    0x2c     ; or something else
            # WoW64 pattern:
            #   4b2fca80: 64 8b 15 30 00 00 00    mov     edx,DWORD PTR fs:0x30
            #   4b2fca87: 8b 92 54 02 00 00       mov     edx,DWORD PTR [edx+0x254]
            #   4b2fca8d: f7 c2 02 00 00 00       test    edx,0x2
            #   4b2fca93: 74 03                   je      0x4b2fca98
            #   4b2fca95: cd 2e                   int     0x2e
            #   4b2fca97: c3                      ret
            #   4b2fca98: ea 9f ca 2f 4b 33 00    jmp     0x33:0x4b2fca9f
            #   4b2fca9f: 41  ff e2               jmp     r10  # 64 bits
            if function_13bytes[:1] == b'\xb8' and function_13bytes[5:6] == b'\xba' and \
                    function_13bytes[0xa:0xd] == b'\xff\xd2\xc2':
                sysnum, = struct.unpack('<I', function_13bytes[1:5])
                syscall_stubs[name] = sysnum

            # 64-bit ntdll.dll with syscall only (11 bytes):
            #   4c 8b d1                mov     r10,rcx
            #   b8 xx xx xx xx          mov     eax,xxxxxxxx
            #   0f 05                   syscall
            #   c3                      ret
            if function_13bytes[:4] == b'\x4c\x8b\xd1\xb8' and \
                    function_13bytes[8:0xb] == b'\x0f\x05\xc3':
                sysnum, = struct.unpack('<I', function_13bytes[4:8])
                syscall_stubs[name] = sysnum

            # 64-bit ntdll.dll on Windows 10 with possible hypervisor (24 bytes):
            #   4c 8b d1                mov     r10,rcx
            #   b8 xx xx xx xx          mov     eax,xxxxxxxx
            #   f6 04 25 08 03 fe 7f 01 test   BYTE PTR ds:0x7ffe0308,0x1 ; _KUSER_SHARED_DATA!SystemCall
            #   75 03                   jne     $+5
            #   0f 05                   syscall
            #   c3                      ret
            #   cd 2e                   int     0x2e
            #   c3                      ret
            if function_24bytes[:4] == b'\x4c\x8b\xd1\xb8' and \
                    function_24bytes[8:0x18] == b'\xf6\x04%\x08\x03\xfe\x7f\x01u\x03\x0f\x05\xc3\xcd.\xc3':
                sysnum, = struct.unpack('<I', function_24bytes[4:8])
                syscall_stubs[name] = sysnum

        if syscall_stubs:
            # Check consistency
            for name, sysnum in syscall_stubs.items():
                continue
                if not re.match(r'^(Nt|Rtl|Zw)[A-Z][0-9A-Za-z_]+$', name):
                    if name == 'EndTask' and self.export_dll_name and self.export_dll_name.upper() == 'USER32.DLL':
                        pass
                    else:
                        raise ValueError("Unexpected name for syscall stub {:#x}: {}".format(sysnum, repr(name)))

                if name.startswith('Nt'):
                    other_name = 'Zw' + name[2:]
                    if other_name not in syscall_stubs:
                        # Only ntdll has syscall stubs
                        if self.export_dll_name and self.export_dll_name.upper() in ('USER32.DLL', 'WIN32U.DLL'):
                            continue
                elif name.startswith('Zw'):
                    other_name = 'Nt' + name[2:]
                elif name == 'RtlGetNativeSystemInformation':
                    other_name = 'NtWow64GetNativeSystemInformation'
                    if other_name not in syscall_stubs:
                        other_name = 'NtQuerySystemInformation'
                else:
                    raise ValueError("Unable to guess a matching syscall name for {}:{:#x}".format(
                        name, sysnum))

                other_sysnum = syscall_stubs.get(other_name)
                if other_sysnum != sysnum:
                    possible_names = set(
                        o_name for o_name, o_sysnum in syscall_stubs.items()
                        if o_sysnum == sysnum and o_name != name)
                    raise ValueError("Unmatched syscall stub {}:{:#x}={}: {}:{} (possible names: {})".format(
                        name, sysnum, sysnum, other_name, other_sysnum,
                        ', '.join(sorted(possible_names))))
            self.syscall_stubs = syscall_stubs

    def get_mssym_pe_url(self, base_url=MICROSOFT_SYMBOLS_URL):
        """Craft an URL where binaries produced by Microsoft are hosted"""
        if not self.pe_file_name:
            return None
        base_url = base_url.rstrip('/')
        pe_file_name = self.pe_file_name
        time_stamp = '{:08X}'.format(self.pe_header.FileHeader.TimeDateStamp)
        image_size = '{:x}'.format(self.pe_header.OptionalHeader.SizeOfImage)
        return '{}/{}/{}{}/{}'.format(base_url, pe_file_name, time_stamp, image_size, pe_file_name)

    def get_mssym_pdb_url(self, base_url=MICROSOFT_SYMBOLS_URL):
        """Craft an URL where debug symbols are hosted for binaries produced by Microsoft, with GUID"""
        if not self.debug_codeview_guid or not self.debug_codeview_path:
            return None
        base_url = base_url.rstrip('/')
        pdb_name = self.debug_codeview_path.rsplit('\\', 1)[-1]
        guid_hex = binascii.hexlify(self.debug_codeview_guid.bytes).decode('ascii').upper()
        age_hex = '{:X}'.format(self.debug_codeview_age)
        return '{}/{}/{}{}/{}'.format(base_url, pdb_name, guid_hex, age_hex, pdb_name)

    def dump(self):
        """Dump a summary of the loaded file"""
        print("* MZDOS Header:")
        dump_struct(self.mzdos_header, indent='  ')

        print("")
        print("* PE Header:")
        dump_struct(self.pe_header, indent='  ')

        print("")
        print("* Section Headers:")
        dump_array_struct(self.section_headers, indent='  ')

        if self.export_directory is not None:
            print("")
            print("* Export Directory Table:")
            dump_struct(self.export_directory, indent='  ')
            print("  * DLL Name: {}".format(repr(self.export_dll_name)))
            if self.exported_functions:
                print("  * Exports:")
                for name in sorted(self.exported_functions.keys()):
                    target = self.exported_functions[name]
                    if isinstance(target, int):
                        desc_target = "{}:{:#x}".format(self.get_section_name(target), target)
                    else:
                        desc_target = "=> {}".format(repr(target))
                    print("    [ord {}] {} = {}".format(
                        self.exported_functions_ord[name], name, desc_target))

        if self.syscall_stubs is not None:
            print("")
            print("* Syscall stubs:")
            syscalls_by_num = {}
            for name, sysnum in self.syscall_stubs.items():
                if sysnum not in syscalls_by_num:
                    syscalls_by_num[sysnum] = set()
                syscalls_by_num[sysnum].add(name)
            for sysnum, names in sorted(syscalls_by_num.items()):
                print("  [{:#8x}] {}".format(sysnum, ', '.join(sorted(names))))

        if self.resources is not None:
            print("")
            print("* {} Resources:".format(len(self.resources)))
            for res_path, res_data, res_codepage in self.resources:
                print("  * {}: {} bytes{}".format(
                    res_path, len(res_data),
                    " (codepage {})".format(res_codepage) if res_codepage != 0 else ""))
            if self.resource_version_info is not None:
                ver_info = self.resource_version_info
                print("  * Version info:")
                print("    * Fixed file info:")
                dump_struct(ver_info.fixed, indent='      ')
                print("    * File version: {}".format(ver_info.file_version))
                print("    * Product version: {}".format(ver_info.product_version))
                dump_dict(ver_info.children, indent='    ')

        if self.signatures:
            print("")
            print("* Authenticode signature:")
            print("  * {} regions excluded from the Authenticode signature:".format(
                len(self.authenticode_excluded)))
            for start, size in self.authenticode_excluded:
                print("    * {:#x}..{:#x} ({} bytes)".format(start, start + size, size))
            last_start, last_size = self.authenticode_excluded[-1]
            last_end = last_start + last_size
            if self.authenticode_file_end == last_start:
                if len(self.file_content) == last_end:
                    print("  * Authenticode signature is at the end of file")
                else:
                    raise ValueError("There are {} unsigned bytes after Authenticode SignedData".format(
                        len(self.file_content) - last_end))
            else:
                print("  * Authenticode signed data stops at {:#x}/{:#x} ({} bytes skipped)".format(
                    self.authenticode_file_end, len(self.file_content),
                    len(self.file_content) - self.authenticode_file_end))
                # TODO: check Authenticode signnature properly
                raise NotImplementedError("Inserted Authenticode signature ?!?")

            sha256_digest = self.compute_authenticode_digest('sha256')
            print("  * SHA256 digest: {}".format(binascii.hexlify(sha256_digest).decode('ascii')))
            print("  * {} PKCS#7 SignedData structure(s)".format(len(self.signatures)))
            for idx, signature in enumerate(self.signatures):
                print("    [{}]: {} bytes".format(idx, len(signature)))

        if self.debug_directories is not None:
            print("")
            print("* Debug Directory:")
            dump_array_struct(self.debug_directories, indent='  ')
            if self.debug_codeview_guid is not None:
                print("  * CODEVIEW PDB 7.0 data:")
                print("    * GUID = {}".format(self.debug_codeview_guid))
                print("    * age = {}".format(self.debug_codeview_age))
                print("    * path = {}".format(repr(self.debug_codeview_path)))
            elif self.debug_codeview_timestamp is not None:
                print("  * CODEVIEW PDB 2.0 data:")
                print("    * signature (timestamp) = {:#x} ({})".format(
                    self.debug_codeview_timestamp,
                    datetime.datetime.utcfromtimestamp(self.debug_codeview_timestamp)))
                print("    * age = {}".format(self.debug_codeview_age))
                print("    * path = {}".format(repr(self.debug_codeview_path)))

            if self.debug_repro_data is not None:
                print("  * Reproducible build data [{} bytes]: {}".format(
                    len(self.debug_repro_data),
                    binascii.hexlify(self.debug_repro_data).decode('ascii')))
                if self.debug_repro_data:
                    print("    * Size = {:#x}".format(self.debug_repro_size))
                    print("    * GUID = {}".format(self.debug_repro_guid))
                    print("    * Unknown = {}".format(binascii.hexlify(self.debug_repro_unknown).decode('ascii')))
                    print("    * Timestamp = {:#x}".format(self.debug_repro_timestamp))
                else:
                    print("    * Empty")

        urls = (
            ('PE file', self.get_mssym_pe_url()),
            ('PDB file', self.get_mssym_pdb_url()),
        )
        if any(url is not None for _, url in urls):
            print("")
            print("* URL on Microsoft Symbol Server:")
            for name, url in urls:
                if url is not None:
                    print("  * {}: {}".format(name, url))


if __name__ == '__main__':
    logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)
    for file_path in sys.argv[1:]:
        print(file_path)
        PEFile(Path(file_path)).dump()
