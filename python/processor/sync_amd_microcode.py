#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# Copyright (c) 2023 Nicolas Iooss
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
"""Extract microcode version from AMD's processor Microcode files

A parser is officially shared on https://github.com/AMDESE/amd_ucode_info and
Linux implements one in
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/microcode_amd.h?h=v6.4
and
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/cpu/microcode/amd.c?h=v6.4
"""
import argparse
import io
import re
import struct
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import FrozenSet, Mapping, Optional, Set, Tuple

from cpu_model import AMD_UCODE_VERSIONS

# As https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/ does not provide a download link,
# use the one provided by Google on
# https://kernel.googlesource.com/pub/scm/linux/kernel/git/firmware/linux-firmware.git/+/refs/heads/main
# and more precisely on directory amd-ucode
LINUX_FIRMWARE_GIT_MAIN_AMD_UCODE_TARGZ_URL = "https://kernel.googlesource.com/pub/scm/linux/kernel/git/firmware/linux-firmware.git/+archive/refs/heads/main/amd-ucode.tar.gz"  # noqa

PLATOMAV_UCODE_GIT_MAIN_ZIP_URL = "https://github.com/platomav/CPUMicrocodes/archive/refs/heads/master.zip"

AMD_UCODE_VERSIONS_PATH = Path(__file__).parent / "amd_microcode_versions.txt"

KNOWN_AMD_UCODE_VERSIONS: FrozenSet[Tuple[int, int, str]] = frozenset(AMD_UCODE_VERSIONS)


# Equivalence table from an ID to CPUID_Fn00000001_EAX
KNOWN_EQUIVALENCE_TABLE: Mapping[int, Tuple[int, ...]] = {
    0x0000: (0x000F00,),
    0x0001: (0x000F01,),
    0x0010: (0x000F10,),
    0x0011: (0x000F11,),
    0x0048: (0x000F48,),
    0x004A: (0x000F4A,),
    0x0050: (0x000F50,),
    0x0051: (0x000F51,),
    0x0150: (0x010F50,),
    0x0210: (0x020F10,),
    0x0401: (0x040F01,),
    0x040A: (0x040F0A,),
    0x0413: (0x040F13,),
    0x0414: (0x040F14,),
    0x041B: (0x040F1B,),
    0x0433: (0x040F33,),
    0x0680: (0x060F80,),
    0x0C1B: (0x0C0F1B,),
    0x0F00: (0x0F0F00,),
    0x0F01: (0x0F0F01,),
    0x1000: (0x100F00,),
    0x1020: (0x100F2A,),
    0x1022: (0x100F22, 0x100F23),
    0x1040: (0x100F40,),
    0x1041: (0x100F42, 0x100F52),
    0x1042: (0x100F42,),
    0x1043: (0x100F43, 0x100F53, 0x100F63),
    0x1062: (0x100F62,),
    0x1080: (0x100F80,),
    0x1081: (0x100F81, 0x100F91),
    0x10A0: (0x100FA0,),
    0x1200: (0x120F00,),
    0x2030: (0x200F30,),
    0x2031: (0x200F31,),
    0x2032: (0x200F32,),
    0x3001: (0x300F01,),
    0x3010: (0x300F10,),
    0x5000: (0x500F00,),
    0x5001: (0x500F01,),
    0x5010: (0x500F10,),
    0x5020: (0x500F20,),
    0x5800: (0x580F00,),
    0x5801: (0x580F01,),
    0x5810: (0x580F10,),
    0x5820: (0x580F20,),
    0x6000: (0x600F00,),
    0x6001: (0x600F01,),
    0x6010: (0x600F10,),
    0x6011: (0x600F11,),
    0x6012: (0x600F12,),
    0x6020: (0x600F20,),
    0x6100: (0x610F00,),
    0x6101: (0x610F01,),
    0x6300: (0x630F00,),
    0x6301: (0x630F01,),
    0x6600: (0x660F00,),
    0x6601: (0x660F01,),
    0x6700: (0x670F00,),
    0x6800: (0x680F00,),
    0x6801: (0x680F01,),
    0x6810: (0x680F10,),
    0x6900: (0x690F00,),
    0x7000: (0x700F00,),
    0x7001: (0x700F01,),
    0x7300: (0x730F00,),
    0x7301: (0x730F01,),
    0x8000: (0x800F00,),
    0x8010: (0x800F10,),
    0x8011: (0x800F11,),
    0x8012: (0x800F12,),
    0x8013: (0x800F13,),
    0x8082: (0x800F82,),
    0x8100: (0x810F00,),
    0x8110: (0x810F10,),
    0x8111: (0x810F11,),
    0x8180: (0x810F80,),
    0x8181: (0x810F81,),
    0x8200: (0x820F00,),
    0x8201: (0x820F01,),
    0x8300: (0x830F00,),
    0x8310: (0x830F10,),
    0x8500: (0x850F00,),
    0x8600: (0x860F00,),
    0x8601: (0x860F01,),
    0x8681: (0x860F81,),
    0x8840: (0x880F40,),
    0x8700: (0x870F00,),
    0x8710: (0x870F10,),
    0x8900: (0x890F00,),
    0x8901: (0x890F01,),
    0x8902: (0x890F02,),
    0x8910: (0x890F10,),
    0x8A00: (0x8A0F00,),
    0xA000: (0xA00F00,),
    0xA010: (0xA00F10,),
    0xA011: (0xA00F11,),
    0xA012: (0xA00F12,),
    0xA080: (0xA00F80,),
    0xA082: (0xA00F82,),
    0xA100: (0xA10F00,),
    0xA101: (0xA10F01,),
    0xA10B: (0xA10F0B,),
    0xA110: (0xA10F10,),
    0xA111: (0xA10F11,),
    0xA112: (0xA10F12,),
    0xA180: (0xA10F80,),
    0xA181: (0xA10F81,),
    0xA200: (0xA20F00,),
    0xA210: (0xA20F10,),
    0xA212: (0xA20F12,),
    0xA400: (0xA40F00,),
    0xA440: (0xA40F40,),
    0xA441: (0xA40F41,),
    0xA500: (0xA50F00,),
    0xA600: (0xA60F00,),
    0xA611: (0xA60F11,),
    0xA612: (0xA60F12,),
    0xA700: (0xA70F00,),
    0xA740: (0xA70F40,),
    0xA741: (0xA70F41,),
    0xA742: (0xA70F42,),
    0xA752: (0xA70F52,),
    0xA780: (0xA70F80,),
    0xA7C0: (0xA70FC0,),
    0xA800: (0xA80F00,),
    0xA801: (0xA80F01,),
    0xA900: (0xA90F00,),
    0xA901: (0xA90F01,),
    0xAA00: (0xAA0F00,),
    0xAA01: (0xAA0F01,),
    0xAA02: (0xAA0F02,),
    0xB000: (0xB00F00,),
    0xB010: (0xB00F10,),
    0xB020: (0xB00F20,),
    0xB021: (0xB00F21,),
    0xB100: (0xB10F00,),
    0xB110: (0xB10F10,),
    0xB240: (0xB20F40,),
    0xB400: (0xB40F00,),
    0xB440: (0xB40F40,),
    0xB600: (0xB60F00,),
}


def parse_amd_ucode(
    ucode_data: bytes, ucode_versions: Optional[Set[Tuple[int, int, str]]] = None, verbose: bool = False
) -> bool:
    """Parse AMD microcode"""
    found_new = False

    (
        year,
        day,
        month,
        patch_id,
        mc_patch_data_id,
        mc_patch_data_len,
        init_flag,
        mc_patch_data_checksum,
        nb_dev_id,
        sb_dev_id,
        processor_rev_id,
        nb_rev_id,
        sb_rev_id,
        bios_api_rev,
    ) = struct.unpack("<HBBIHBBIIIHBBB", ucode_data[:0x1D])

    # The date is encoded "decimal as hexadecimal"
    date = f"{year:04x}-{month:02x}-{day:02x}"
    cpuids = KNOWN_EQUIVALENCE_TABLE.get(processor_rev_id)
    if cpuids is None:
        print(f"Warning: unknown processor equivalence ID {processor_rev_id:#x}")
        cpuids = tuple()

    if verbose:
        # print(f"  {date} {patch_id:#010x} {mc_patch_data_id:#x} {mc_patch_data_len:#x} {init_flag:#x} {nb_dev_id:#x} {sb_dev_id:#x} {processor_rev_id:#x} {nb_rev_id:#x} {sb_rev_id:#x} {bios_api_rev:#x}")  # noqa
        hex_cpuids = ", ".join(f"{cpuid:#08x}" for cpuid in cpuids)
        print(f"  {date} patch {patch_id:#010x} proc {processor_rev_id:#x} -> {hex_cpuids}")

    for cpuid in cpuids:
        if ucode_versions is not None:
            ucode_versions.add((cpuid, patch_id, date))
        if (cpuid, patch_id, date) not in KNOWN_AMD_UCODE_VERSIONS:
            found_new = True
            print(f"  {date} cpuid {cpuid:#07x} rev {patch_id:#010x} NEW!")
    return found_new


def parse_amd_ucode_container(
    file_data: bytes, ucode_versions: Optional[Set[Tuple[int, int, str]]] = None, verbose: bool = False
) -> bool:
    """Parse AMD microcode containers, which contain an equivalence table and several sections"""
    found_new = False
    if not file_data.startswith(b"DMA\0"):
        raise ValueError(f"Invalid file magic in AMD microcode container: {file_data[:4]!r}")

    container_type, equiv_table_size = struct.unpack("<II", file_data[4:0xC])
    if container_type != 0:
        raise ValueError(f"Invalid container type for equivalence table: {container_type:#x}")
    if equiv_table_size < 0x10 or (equiv_table_size % 0x10) != 0:
        raise ValueError(f"Invalid size of equivalence table: {equiv_table_size:#x}")

    for tbl_offset in range(0, equiv_table_size, 0x10):
        data_start = 0xC + tbl_offset
        data_end = data_start + 0x10
        installed_cpu, fixed_errata_mask, fixed_errata_compare, equiv_cpu, reserved = struct.unpack(
            "<IIIHH", file_data[data_start:data_end]
        )
        if fixed_errata_mask != 0 or fixed_errata_compare != 0 or reserved != 0:
            raise ValueError(
                f"Unexpected content in equivalence table: {fixed_errata_mask:#x} {fixed_errata_compare:#x} {reserved:#x}"  # noqa
            )
        if installed_cpu == 0 and equiv_cpu == 0:
            continue
        if equiv_cpu not in KNOWN_EQUIVALENCE_TABLE:
            print(f"Warning: mapping 0x{equiv_cpu:X}: 0x{installed_cpu:X} is missing in the known equivalence table")
        elif installed_cpu not in KNOWN_EQUIVALENCE_TABLE[equiv_cpu]:
            raise ValueError(
                f"Missing equivalence for 0x{equiv_cpu:X}: 0x{installed_cpu:X} not in {KNOWN_EQUIVALENCE_TABLE[equiv_cpu]}"  # noqa
            )

    offset = 0xC + equiv_table_size
    while offset < len(file_data):
        # Read a container header
        offset_end = offset + 8
        container_type, ucode_size = struct.unpack("<II", file_data[offset:offset_end])
        if container_type != 1:
            raise ValueError(f"Invalid container type for ucode: {container_type:#x}")
        offset += 8 + ucode_size
        if parse_amd_ucode(file_data[offset_end:offset], ucode_versions=ucode_versions, verbose=verbose):
            found_new = True
    return found_new


def parse_amd_ucode_directory(
    directory: Path, ucode_versions: Optional[Set[Tuple[int, int, str]]] = None, verbose: bool = False
) -> None:
    """Parse files present in a clone of linux-firmare"""
    for ucode_file in sorted(directory.glob("**/amd-ucode/*.bin")):
        if verbose:
            print(f"Parsing {ucode_file.absolute()}")
        with ucode_file.open("rb") as stream:
            file_data = stream.read()
        if parse_amd_ucode_container(file_data, ucode_versions=ucode_versions, verbose=verbose) and not verbose:
            print(f"  ... found in {ucode_file.absolute()}")

    # Parse also directories like the one from https://github.com/platomav/CPUMicrocodes
    for ucode_file in sorted(directory.glob("**/AMD/*.bin")):
        if verbose:
            print(f"Parsing {ucode_file.absolute()}")
        with ucode_file.open("rb") as stream:
            file_data = stream.read()
        if parse_amd_ucode(file_data, ucode_versions=ucode_versions, verbose=verbose) and not verbose:
            print(f"  ... found in {ucode_file.absolute()}")


def update_amd_microcode_versions(ucode_versions: Set[Tuple[int, int, str]]) -> None:
    """Update amd_microcode_versions.txt with the new microcode version"""
    # Read the file header
    file_header = []
    with AMD_UCODE_VERSIONS_PATH.open("r") as fin:
        for line in fin:
            if line.startswith("0x"):
                break
            file_header.append(line)
    new_ucode_versions = sorted(KNOWN_AMD_UCODE_VERSIONS.union(ucode_versions))

    print(f"Updating {AMD_UCODE_VERSIONS_PATH}")
    with AMD_UCODE_VERSIONS_PATH.open("w") as fout:
        for line in file_header:
            print(line, file=fout, end="")
        for cpuid, version, date in new_ucode_versions:
            print(f"{cpuid:#08x}  {version:#10x}  {date}", file=fout)


def parse_amd_ucode_from_git(ucode_versions: Optional[Set[Tuple[int, int, str]]] = None, verbose: bool = False) -> None:
    """Download AMD microcodes from linux-firmware's main branch and analyze it"""
    if verbose:
        print(f"Downloading {LINUX_FIRMWARE_GIT_MAIN_AMD_UCODE_TARGZ_URL}")
    with urllib.request.urlopen(LINUX_FIRMWARE_GIT_MAIN_AMD_UCODE_TARGZ_URL) as response:
        targz_data = response.read()
    with tarfile.open(fileobj=io.BytesIO(targz_data), mode="r:gz") as archive:
        for file_info in archive.getmembers():
            if file_info.isdir():
                continue
            if re.match(r"^.*\.bin$$", file_info.name):
                if verbose:
                    print(f"Parsing {file_info.name}")
                archive_file = archive.extractfile(file_info.name)
                assert archive_file is not None
                file_data = archive_file.read()
                if parse_amd_ucode_container(file_data, ucode_versions=ucode_versions, verbose=verbose) and not verbose:
                    print(f"  ... found in linux-firmware's amd-ucode/{file_info.name}")


def parse_platomav_amd_microcode_from_github(
    ucode_versions: Optional[Set[Tuple[int, int, str]]] = None, verbose: bool = False
) -> None:
    """Download Platomav microcode's main branch and analyze it"""
    if verbose:
        print(f"Downloading {PLATOMAV_UCODE_GIT_MAIN_ZIP_URL}")
    with urllib.request.urlopen(PLATOMAV_UCODE_GIT_MAIN_ZIP_URL) as response:
        zip_data = response.read()
    with zipfile.ZipFile(io.BytesIO(zip_data), "r") as archive:
        for file_info in archive.infolist():
            if file_info.is_dir():
                continue
            if re.match(r"^.*/AMD/.*\.bin$", file_info.filename):
                if verbose:
                    print(f"Parsing {file_info.filename}")
                file_data = archive.read(file_info.filename)
                if parse_amd_ucode(file_data, ucode_versions=ucode_versions, verbose=verbose) and not verbose:
                    print(f"  ... found in Platomav's {file_info.filename}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synchronize with AMD microcode releases")
    parser.add_argument(
        "firmware",
        nargs="?",
        type=Path,
        help="directory where https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git is cloned (optional)",  # noqa
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    parser.add_argument("-w", "--write", action="store_true", help="update amd_microcode_versions.txt automatically")
    args = parser.parse_args()

    ucode_versions: Set[Tuple[int, int, str]] = set()

    if args.firmware:
        parse_amd_ucode_directory(args.firmware, ucode_versions=ucode_versions, verbose=args.verbose)
    else:
        parse_amd_ucode_from_git(ucode_versions=ucode_versions, verbose=args.verbose)
        parse_platomav_amd_microcode_from_github(ucode_versions=ucode_versions, verbose=args.verbose)

    new_ucode_versions = ucode_versions - KNOWN_AMD_UCODE_VERSIONS
    if args.verbose or new_ucode_versions:
        print(f"Found {len(ucode_versions)} distinct microcodes, {len(new_ucode_versions)} new")

    if new_ucode_versions and args.write:
        update_amd_microcode_versions(ucode_versions)
