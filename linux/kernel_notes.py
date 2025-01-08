#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
"""Parse /sys/kernel/notes

According to https://www.kernel.org/doc/Documentation/ABI/stable/sysfs-kernel-notes

    The /sys/kernel/notes file contains the binary representation of the running
    vmlinux's .notes section.

In practice, it contains information related to Xen, defined in
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/xen/xen-head.S?h=v6.8#n90

It contains list of structures with headers:
(from https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/elf.h )

    /* Note header in a PT_NOTE section */
    typedef struct elf32_note {
      Elf32_Word  n_namesz;  /* Name size */
      Elf32_Word  n_descsz;  /* Content size */
      Elf32_Word  n_type;    /* Content type */
    } Elf32_Nhdr;

    /* Note header in a PT_NOTE section */
    typedef struct elf64_note {
      Elf64_Word n_namesz;  /* Name size */
      Elf64_Word n_descsz;  /* Content size */
      Elf64_Word n_type;  /* Content type */
    } Elf64_Nhdr;

This /sys/kernel/notes is created when initialized the sysfs by
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/ksysfs.c?h=v6.8#n226

In April 2024, there was a proposal to make /sys/kernel/notes restricted to root:
https://lore.kernel.org/all/202402180028.6DB512C50@keescook/

To test on a normal ELF program:

    ./kernel_notes.py <(objcopy -j '.note*' /bin/sh -O binary /dev/stdout)

The notes sections are also decoded with:

    readelf -n /bin/sh
"""
from __future__ import annotations

import argparse
import enum
import re
import struct
import sys
from pathlib import Path
from typing import Sequence


@enum.unique
class NoteTypeGnu(enum.IntEnum):
    NT_GNU_ABI_TAG = 1  # Section .note.ABI-tag
    NT_GNU_HWCAP = 2
    NT_GNU_BUILD_ID = 3  # Section .note.gnu.build-id
    NT_GNU_GOLD_VERSION = 4
    NT_GNU_PROPERTY_TYPE_0 = 5  # Section .note.gnu.property


@enum.unique
class NoteTypeLinux(enum.IntEnum):
    LINUX_ELFNOTE_VERSION = 0  # Contains LINUX_VERSION_CODE in vDSO
    LINUX_ELFNOTE_BUILD_SALT = 0x100  # Contains CONFIG_BUILD_SALT
    LINUX_ELFNOTE_LTO_INFO = 0x101  # Contains CONFIG_LTO


# From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/xen/interface/elfnote.h?h=v6.12
@enum.unique
class NoteTypeXen(enum.IntEnum):
    XEN_ELFNOTE_INFO = 0
    XEN_ELFNOTE_ENTRY = 1  # Address of startup_xen (KASLR leak)
    XEN_ELFNOTE_HYPERCALL_PAGE = 2  # Address of hypercall_page
    XEN_ELFNOTE_VIRT_BASE = 3
    XEN_ELFNOTE_PADDR_OFFSET = 4
    XEN_ELFNOTE_XEN_VERSION = 5
    XEN_ELFNOTE_GUEST_OS = 6
    XEN_ELFNOTE_GUEST_VERSION = 7
    XEN_ELFNOTE_LOADER = 8
    XEN_ELFNOTE_PAE_MODE = 9
    XEN_ELFNOTE_FEATURES = 10
    XEN_ELFNOTE_BSD_SYMTAB = 11
    XEN_ELFNOTE_HV_START_LOW = 12
    XEN_ELFNOTE_L1_MFN_VALID = 13
    XEN_ELFNOTE_SUSPEND_CANCEL = 14
    XEN_ELFNOTE_INIT_P2M = 15
    XEN_ELFNOTE_MOD_START_PFN = 16
    XEN_ELFNOTE_SUPPORTED_FEATURES = 17
    XEN_ELFNOTE_PHYS32_ENTRY = 18
    XEN_ELFNOTE_PHYS32_RELOC = 19
    XEN_ELFNOTE_CRASH_INFO = 0x1000001
    XEN_ELFNOTE_CRASH_REGS = 0x1000002
    XEN_ELFNOTE_DUMPCORE_NONE = 0x2000000
    XEN_ELFNOTE_DUMPCORE_HEADER = 0x2000001
    XEN_ELFNOTE_DUMPCORE_XEN_VERSION = 0x2000002
    XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION = 0x2000003


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the randomness of memory addresses")
    parser.add_argument(
        "notes", type=Path, nargs="?", default=Path("/sys/kernel/notes"), help="copy of /sys/kernel/notes to decode"
    )
    args = parser.parse_args(argv)

    notes_path: Path = args.notes
    with notes_path.open("rb") as f:
        notes = f.read()

    # Guess the endianness from the first bytes, which is 32-bit n_namesz
    if notes.startswith(b"\0\0"):
        endianness = ">"
    elif notes[2:4] == b"\0\0":
        endianness = "<"
    else:
        print(f"Unable to guess the endianness: {notes[:4].hex()}", file=sys.stderr)
        return 1

    offset = 0
    while offset < len(notes):
        if offset + 12 > len(notes):
            print(f"Truncated header: {notes[offset:].hex()}", file=sys.stderr)
            return 1
        n_namesz, n_descsz, n_type = struct.unpack(f"{endianness}3I", notes[offset:offset + 12])
        offset += 12
        if offset + n_namesz + n_descsz > len(notes):
            print(f"Invalid header with large sizes: {n_namesz:#x}, {n_descsz:#x}, {n_type:#x}", file=sys.stderr)
            return 1
        n_name = notes[offset:offset + n_namesz]
        offset += n_namesz
        if padding_size := (4 - offset) & 3:
            padding = notes[offset:offset + padding_size]
            if padding != b"\0" * padding_size:
                print(f"Warning: invalid name padding at {offset:#x}", file=sys.stderr)
            offset += padding_size
        n_desc = notes[offset:offset + n_descsz]
        offset += n_descsz
        if padding_size := (4 - offset) & 3:
            padding = notes[offset:offset + padding_size]
            if padding != b"\0" * padding_size:
                print(f"Warning: invalid desc padding at {offset:#x}", file=sys.stderr)
            offset += padding_size
        assert len(n_name) == n_namesz
        assert len(n_desc) == n_descsz

        # Generate a description
        type_str = str(n_type)
        desc_str = repr(n_desc)
        if n_name == b"GNU\0":
            name_str = "GNU"
            type_gnu = NoteTypeGnu(n_type)
            type_str = f"{type_gnu.name}={n_type}"
            if type_gnu == NoteTypeGnu.NT_GNU_ABI_TAG and len(n_desc) == 0x10:
                # Decode OS type:
                #     #define ELF_NOTE_OS_LINUX     0
                #     #define ELF_NOTE_OS_GNU       1
                #     #define ELF_NOTE_OS_SOLARIS2  2
                #     #define ELF_NOTE_OS_FREEBSD   3
                os_type, major, minor, subminor = struct.unpack(f"{endianness}4I", n_desc)
                os_type_str = {
                    0: "Linux",
                    1: "GNU",
                    2: "Solaris2",
                    3: "FreeBSD",
                }.get(os_type, f"? ({os_type})")
                desc_str = f"OS {os_type_str} ABI {major}.{minor}.{subminor}"
            elif type_gnu == NoteTypeGnu.NT_GNU_BUILD_ID:
                desc_str = n_desc.hex()
            elif type_gnu == NoteTypeGnu.NT_GNU_PROPERTY_TYPE_0:
                pr_offset = 0
                pr_parts: list[str] = []
                while pr_offset < len(n_desc):
                    pr_type, pr_datasz = struct.unpack(f"{endianness}2I", n_desc[pr_offset:pr_offset + 8])
                    pr_offset += 8
                    if pr_offset + pr_datasz > len(n_desc):
                        print(f"Invalid .note.gnu.property size: {pr_type:#x}, {pr_datasz:#x}", file=sys.stderr)
                        return 1
                    pr_data = n_desc[pr_offset:pr_offset + pr_datasz]
                    pr_offset += pr_datasz
                    if padding_size := (4 - pr_offset) & 3:
                        padding = n_desc[pr_offset:pr_offset + padding_size]
                        if padding != b"\0" * padding_size:
                            print(f"Warning: invalid .note.gnu.property padding at {pr_offset:#x}", file=sys.stderr)
                        pr_offset += padding_size
                    if (pr_offset & 7) == 4 and n_desc[pr_offset:pr_offset + 4] == b"\0" * 4:
                        # 64-bit padding
                        pr_offset += 4

                    # From https://github.com/gimli-rs/object/blob/0.35.0/src/elf.rs#L1889
                    #   GNU_PROPERTY_STACK_SIZE = 1
                    #   GNU_PROPERTY_NO_COPY_ON_PROTECTED = 2
                    #   GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xc0000000
                    #       bit 0 is BTI
                    #       bit 1 is PAC
                    #   GNU_PROPERTY_AARCH64_FEATURE_PAUTH = 0xc0000001
                    #   GNU_PROPERTY_X86_ISA_1_USED = 0xc0010002
                    #       bit 0 is BASELINE
                    #       bit 1 is V2
                    #       bit 2 is V3
                    #       bit 3 is V4
                    #   GNU_PROPERTY_X86_ISA_1_NEEDED = 0xc0008002
                    #   GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002
                    #       bit 0 is IBT
                    #       bit 1 is SHSTK
                    # From https://bugzilla.redhat.com/show_bug.cgi?id=1916925
                    #   GNU_PROPERTY_X86_UINT32_AND_LO = 0xc0000002
                    #   GNU_PROPERTY_X86_UINT32_AND_HI = 0xc0007fff
                    #   GNU_PROPERTY_X86_UINT32_OR_LO = 0xc0008000
                    #   GNU_PROPERTY_X86_UINT32_OR_HI = 0xc000ffff
                    #   GNU_PROPERTY_X86_UINT32_OR_AND_LO = 0xc0010000
                    #   GNU_PROPERTY_X86_UINT32_OR_AND_HI = 0xc0017fff
                    # https://github.com/bminor/binutils-gdb/blob/binutils-2_42/gold/testsuite/gnu_property_a.S
                    #   GNU_PROPERTY_X86_ISA_1_USED = 0xc0010002
                    #   GNU_PROPERTY_X86_ISA_1_NEEDED = 0xc0008002
                    #   GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002
                    # https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=include/elf/common.h;h=1a940ff7b52c779f07cf69032f33af46c404e1e9;hb=9eef0608951ba0e551dd6dd079ce1e20bae11f6b
                    #   GNU_PROPERTY_X86_ISA_1_USED = 0xc0000000
                    #   GNU_PROPERTY_X86_ISA_1_NEEDED = 0xc0000001
                    #   GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002
                    # https://github.com/bminor/binutils-gdb/blob/binutils-2_42/include/elf/common.h
                    # and https://gitlab.com/x86-psABIs/x86-64-ABI/-/merge_requests/1
                    #   GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002
                    #       bit 0 is IBT (Indirect Branch Tracking)
                    #       bit 1 is SHSTK (Shadow Stack)
                    #       bit 2 is LAM_U48 (Linear Address Masking (LAM))
                    #       bit 3 is LAM_U57
                    #   GNU_PROPERTY_X86_ISA_1_NEEDED = 0xc0008002
                    #   GNU_PROPERTY_X86_ISA_1_USED = 0xc0010002
                    #   GNU_PROPERTY_X86_FEATURE_2_NEEDED = 0xc0008001
                    #   GNU_PROPERTY_X86_FEATURE_2_USED = 0xc0010001
                    #       bit 0 is X86
                    #       bit 1 is X87
                    #       bit 2 is MMX
                    #       bit 3 is XMM
                    #       bit 4 is YMM
                    #       bit 5 is ZMM
                    #       bit 6 is FXSR
                    #       bit 7 is XSAVE
                    #       bit 8 is XSAVEOPT
                    #       bit 9 is XSAVEC
                    #       bit 10 is TMM
                    #       bit 11 is MASK
                    pr_type_str = {
                        1: "STACK_SIZE",
                        2: "NO_COPY_ON_PROTECTED",
                        0xc0000000: "AARCH64_FEATURE_1_AND",
                        0xc0000001: "AARCH64_FEATURE_PAUTH",
                        0xc0000002: "X86_U32_AND_LO",
                        0xc0010001: "X86_FEATURE_2_USED",
                        0xc0010002: "X86_ISA_1_USED",
                        0xc0007fff: "X86_U32_AND_HI",
                        0xc0008000: "X86_U32_OR_LO",
                        0xc0008001: "X86_FEATURE_2_NEEDED",
                        0xc0008002: "X86_ISA_1_NEEDED",
                        0xc000ffff: "X86_U32_OR_HI",
                        0xc0010000: "X86_U32_OR_AND_LO",
                        0xc0017fff: "X86_U32_OR_AND_HI",
                    }.get(pr_type, f"? ({pr_type:#x})")
                    if pr_type == 0xc0000002 and pr_data == b"\x03\0\0\0":  # X86_U32_AND_LO
                        pr_parts.append(f"{pr_type_str}=IBT|SHSTK (3)")
                    elif pr_type == 0xc0008002 and pr_data == b"\x01\0\0\0":  # X86_ISA_1_NEEDED
                        pr_parts.append(f"{pr_type_str}=x86-64-baseline (1)")
                    elif pr_type == 0xc0010001 and pr_data == b"\x0b\0\0\0":  # X86_FEATURE_2_USED
                        pr_parts.append(f"{pr_type_str}=x86|x87|xmm (0xb)")
                    elif pr_type == 0xc0010002 and pr_data == b"\x01\0\0\0":  # X86_ISA_1_USED
                        pr_parts.append(f"{pr_type_str}=x86-64-baseline (1)")
                    else:
                        pr_parts.append(f"{pr_type_str}={pr_data.hex()}")
                desc_str = ", ".join(pr_parts)
        elif n_name == b"Linux\0":
            name_str = "Linux"
            type_linux = NoteTypeLinux(n_type)
            type_str = f"{type_linux.name}={n_type}"
            if type_linux == NoteTypeLinux.LINUX_ELFNOTE_VERSION and len(n_desc) == 4:
                linux_ver_int, = struct.unpack(f"{endianness}I", n_desc)
                major = linux_ver_int >> 16
                minor = (linux_ver_int >> 8) & 0xFF
                patch = linux_ver_int & 0xFF
                desc_str = f"{major}.{minor}.{patch}"
            elif type_linux == NoteTypeLinux.LINUX_ELFNOTE_LTO_INFO and len(n_desc) == 4:
                lto_info, = struct.unpack(f"{endianness}I", n_desc)
                desc_str = str(lto_info)
        elif n_name == b"Xen\0":
            name_str = "Xen"
            type_xen = NoteTypeXen(n_type)
            type_str = f"{type_xen.name}={n_type}"
            if type_xen in {
                NoteTypeXen.XEN_ELFNOTE_INFO,
                NoteTypeXen.XEN_ELFNOTE_XEN_VERSION,
                NoteTypeXen.XEN_ELFNOTE_GUEST_OS,
                NoteTypeXen.XEN_ELFNOTE_GUEST_VERSION,
                NoteTypeXen.XEN_ELFNOTE_LOADER,
                NoteTypeXen.XEN_ELFNOTE_PAE_MODE,
                NoteTypeXen.XEN_ELFNOTE_FEATURES,
            }:
                # Decode strings
                if not re.match(rb"^[0-9a-zA-Z!|_.-]*(\0?)$", n_desc):
                    print(f"Warning: unexpected value {n_desc!r}")
                else:
                    desc_str = repr(n_desc.rstrip(b"\0").decode("ascii"))
            elif type_xen in {
                NoteTypeXen.XEN_ELFNOTE_ENTRY,
                NoteTypeXen.XEN_ELFNOTE_HYPERCALL_PAGE,
                NoteTypeXen.XEN_ELFNOTE_VIRT_BASE,
                NoteTypeXen.XEN_ELFNOTE_PADDR_OFFSET,
                NoteTypeXen.XEN_ELFNOTE_HV_START_LOW,
                NoteTypeXen.XEN_ELFNOTE_INIT_P2M,
                NoteTypeXen.XEN_ELFNOTE_MOD_START_PFN,
                NoteTypeXen.XEN_ELFNOTE_SUPPORTED_FEATURES,
                NoteTypeXen.XEN_ELFNOTE_PHYS32_ENTRY,
            }:
                # Decode numbers
                if len(n_desc) == 4:
                    value, = struct.unpack(f"{endianness}I", n_desc)
                    desc_str = f"{value:#010x}"
                elif len(n_desc) == 8:
                    value, = struct.unpack(f"{endianness}Q", n_desc)
                    desc_str = f"{value:#018x}"
            elif type_xen == NoteTypeXen.XEN_ELFNOTE_SUSPEND_CANCEL and len(n_desc) == 4:
                # Decode small numbers (0 or 1)
                value, = struct.unpack(f"{endianness}I", n_desc)
                desc_str = str(value)
            elif type_xen == NoteTypeXen.XEN_ELFNOTE_L1_MFN_VALID and len(n_desc) == 16:
                # Decode (PG_V, PG_V) from 
                # https://github.com/mirage/xen/blob/RELEASE-4.8.1/docs/misc/pvh.markdown
                # and
                # https://xenbits.xen.org/docs/4.3-testing/hypercall/include,public,elfnote.h.html
                mask, value = struct.unpack(f"{endianness}2Q", n_desc)
                desc_str = f"mask={mask:#x}, value={value:#x}"
            elif type_xen == NoteTypeXen.XEN_ELFNOTE_PHYS32_RELOC and len(n_desc) == 12:
                # Decode 3 32-bit values from
                # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/platform/pvh/head.S?h=v6.12#n297
                # (CONFIG_PHYSICAL_ALIGN, LOAD_PHYSICAL_ADDR, KERNEL_IMAGE_SIZE - 1)
                phys_align, load_phys_addr, load_max = struct.unpack(f"{endianness}3I", n_desc)
                desc_str = f"align={phys_align:#x}, addr={load_phys_addr:#x}, max={load_max:#x}"
        else:
            print(f"Warning: unknown name {n_name!r}", file=sys.stderr)
            name_str = repr(n_name)

        print(f"{name_str}/{type_str}: {desc_str}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
