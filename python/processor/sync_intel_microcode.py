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
"""Extract information from Intel's processor Microcode releases

https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files contains
useful information
"""
import argparse
import io
import re
import struct
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import FrozenSet, List, Optional, Set, Tuple

from cpu_model import CPU_MODELS, INTEL_UCODE_VERSIONS

INTEL_UCODE_GIT_MAIN_ZIP_URL = (
    "https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/archive/refs/heads/main.zip"
)
PLATOMAV_UCODE_GIT_MAIN_ZIP_URL = "https://github.com/platomav/CPUMicrocodes/archive/refs/heads/master.zip"

INTEL_UCODE_VERSIONS_PATH = Path(__file__).parent / "intel_microcode_versions.txt"

KNOWN_INTEL_UCODE_VERSIONS: FrozenSet[Tuple[int, int, str]] = frozenset(INTEL_UCODE_VERSIONS)


# Track whether the CPUID database needs to be updated
cpuid_db_needs_update: bool = False


def expand_proc_acronym(acronym: str) -> List[str]:
    """Expand a processor acronym to a list of acronyms"""
    expanded = []
    current_prefix = ""
    for acr in acronym.split("/"):
        parts = acr.split("-", 1)
        if len(parts) >= 2:
            expanded.append(acr)
            current_prefix = parts[0]
        elif current_prefix:
            expanded.append(current_prefix + "-" + acr)
        else:
            expanded.append(acr)
    return expanded


# Self-checks
assert expand_proc_acronym("BDW") == ["BDW"]
assert expand_proc_acronym("CFL-H/S/E3") == ["CFL-H", "CFL-S", "CFL-E3"]
assert expand_proc_acronym("KBL-U/Y/AML-Y22") == ["KBL-U", "KBL-Y", "AML-Y22"]


def parse_intel_ucode_releasenote_cfg(file_data: str) -> None:
    """Parse Intel Microcode release notes"""
    global cpuid_db_needs_update
    in_table = False
    intel_fam6_cpu_models = CPU_MODELS["GenuineIntel"][6]
    for line in file_data.splitlines():
        if not in_table:
            if line.startswith("| Processor"):
                # Start a table
                if line != "| Processor      | Stepping | F-M-S/PI    | Old Ver  | New Ver  | Products":
                    raise ValueError(f"Unexpected table header {line!r}")
                in_table = True
            continue

        if not line:
            in_table = False
            continue

        # Separator "|:---------------|:---..."
        if all(c in "|:-" for c in line):
            continue
        if not line.startswith("| "):
            raise ValueError(f"Unexpected table line {line!r}")
        fields = [column.strip() for column in line[1:].split("|", 5)]
        if len(fields) != 6:
            raise ValueError(f"Unexpected table length in {line!r}")

        # Extract the processor acronym
        field_acronym = fields[0].replace(" ", "-")
        if field_acronym.endswith(("-2+8", "-6+8")):
            # Remove suffixes such as "6+8"
            field_acronym = field_acronym.rsplit("-", 1)[0]

        field_product_name = fields[5]

        # Extract the CPUID
        matches = re.match(r"^06-([0-9a-f][0-9a-f])-([0-9a-f][0-9a-f])/[0-9a-f][0-9a-f]$", fields[2], re.I)
        if not matches:
            raise ValueError(f"Unexpected F-M-S/PI in {line!r}")
        cpuid_model = int(matches.group(1), 16)
        cpuid_stepping = int(matches.group(2), 16)
        cpuid_desc = f"Intel fam6, {cpuid_model:#x}, {cpuid_stepping}"
        cpuid_value = ((cpuid_model & 0xF0) << 12) | (6 << 8) | ((cpuid_model & 0xF) << 4) | cpuid_stepping
        cpuid_data = intel_fam6_cpu_models.get((cpuid_model, cpuid_stepping))
        if cpuid_data is None:
            print(f"Update({cpuid_value:#x}): {cpuid_desc} is {field_acronym} ({field_product_name!r})")
            cpuid_db_needs_update = True
            continue

        # Compare acronyms
        db_acronym = cpuid_data.acronym

        if not re.match(r"^[0-9A-Ze/-]+$", field_acronym):
            raise ValueError(f"Unexpected processor acronym {field_acronym!r} in {line!r}")

        if db_acronym is None:
            # Add a new acronym
            print(f"Update({cpuid_value:#x}): {cpuid_desc} has acronym {field_acronym} ({field_product_name!r})")
            cpuid_db_needs_update = True
            continue

        if db_acronym != field_acronym:
            expanded_db_acronyms = set(expand_proc_acronym(db_acronym))
            for expanded_field_acronym in expand_proc_acronym(field_acronym):
                if expanded_field_acronym not in expanded_db_acronyms:
                    print(
                        f"Update({cpuid_value:#x}): {cpuid_desc} ({db_acronym}) has also {expanded_field_acronym} from {field_acronym} ({field_product_name!r})"  # noqa
                    )
                    cpuid_db_needs_update = True
                    continue

        # Gather information about Core generation
        db_names: Set[str] = set(cpuid_data.desc_list)
        new_names: List[str] = []
        if field_product_name == "Pentium Silver N/J5xxx, Celeron N/J4xxx":
            new_names = ["Intel® Pentium® Silver processors N5xxx, J5xxx", "Intel® Celeron® processors N4xxx, J4xxx"]
        elif field_product_name == "Xeon D-1518/19/21/27/28/31/33/37/41/48, Pentium D1507/08/09/17/19":
            new_names = [
                "Intel® Xeon® Processor D-1518, D-1519, D-1521, D-1527, D-1528, D-1531, D-1533, D-1537, D-1541, D-1548",
                "Intel® Pentium® Processor D1507, D1508, D1509, D1517, D1519",
            ]
        elif field_product_name == "Celeron N2xxx, Pentium N35xx":
            new_names = [
                "Intel® Pentium® Processor N35xx",
                "Intel® Celeron® Processor N2xxx",
            ]
        elif field_product_name == "Pentium N/J4xxx, Celeron N/J3xxx, Atom x5/7-E39xx":
            new_names = [
                "Intel® Pentium® Processor N4xxx/J4xxx",
                "Intel® Celeron® Processor N3xxx/J3xxx",
                "Intel® Atom® Processor x5/x7-E39xx",
            ]
        elif field_product_name == "Pentium J5005/N5000, Celeron J4005/J4105/N4000/N4100":
            new_names = [
                "Intel® Pentium® Silver Processor J5005, N5000",
                "Intel® Celeron® Processor J4005, J4105",
                "Intel® Celeron® Processor N4000, N4100",
            ]
        elif field_product_name == "Pentium J5040/N5030, Celeron J4125/J4025/N4020/N4120":
            new_names = [
                "Intel® Pentium® Silver J5040 Processor",
                "Intel® Pentium® Silver N5030 Processor",
                "Intel® Celeron® Processor J4125",
                "Intel® Celeron® Processor J4025",
                "Intel® Celeron® Processor N4020",
                "Intel® Celeron® Processor N4120",
            ]
        elif field_product_name == "Pentium J6426/N6415, Celeron J6412/J6413/N6210/N6211, Atom x6000E":
            new_names = [
                "Intel® Pentium® J6426/N6415",
                "Intel® Celeron® J6412/J6413/N6210/N6211",
                "Intel® Atom® x6000E",
            ]
        elif field_product_name == "Pentium N6000/N6005, Celeron N4500/N4505/N5100/N5105":
            new_names = ["Intel® Pentium® N6000/N6005", "Intel® Celeron® N4500/N4505/N5100/N5105"]
        elif field_product_name == "Core Gen7/Gen8":
            new_names = ["7th Generation Intel® Core™ Processor Family", "8th Generation Intel® Core™ Processor Family"]
        elif field_product_name == "Core Gen3 X Series; Xeon E5 v2":
            new_names = ["3rd Generation Intel® Core™ Processor Family", "Intel® Xeon® Processor E5v2 Product Family"]
        elif field_product_name == "Core Gen4 X series; Xeon E5 v3":
            new_names = ["4th Generation Intel® Core™ Processor Family", "Intel® Xeon® Processor E5v3 Product Family"]
        elif field_product_name == "Core Gen6; Xeon E3 v5":
            new_names = ["6th Generation Intel® Core™ Processor Family", "Intel® Xeon® Processor E3 v5 Product Family"]
        elif field_product_name == "Core Gen7; Xeon E3 v6":
            new_names = ["7th Generation Intel® Core™ Processor Family", "Intel® Xeon® Processor E3 v6 Product Family"]
        elif field_product_name == "Core Gen7 Desktop, Mobile, Xeon E3 v6":
            new_names = [
                "7th Generation Intel® Core™ Processor Family",
                "7th Generation Intel® Core™ Mobile Processor Family",
                "Intel® Xeon® Processor E3 v6 Product Family",
            ]
        elif field_product_name == "Core w/Hybrid Technology":
            new_names = ["Intel® Core™ Processor with Hybrid Technology"]
        elif field_product_name == "Core™ Ultra Processor":
            new_names = ["Intel® Core™ Ultra Processor"]
        elif field_product_name == "Core i3-N305/N300, N50/N97/N100/N200, Atom x7211E/x7213E/x7425E":
            new_names = [
                "Intel® Core i3-N305/N300",
                "Intel® Processor N50/N97/N100/N200",
                "Intel® Atom® Processor x7211E/x7213E/x7425E",
            ]
        elif field_product_name == "Atom x5/7-E39xx":
            new_names = [
                "Intel® Atom® Processor x5-E39xx",
                "Intel® Atom® Processor x7-E39xx",
            ]
        elif field_product_name == "Intel(R) Atom(R) C1100":
            new_names = ["Intel® Atom® Processor C1100"]
        elif field_product_name == "Xeon Scalable":
            new_names = ["Intel® Xeon® Scalable Processor Family"]
        elif field_product_name == "Xeon Scalable Gen2":
            new_names = ["2nd Generation Intel® Xeon® Scalable Processor Family"]
        elif field_product_name == "Xeon Scalable Gen3":
            new_names = ["3rd Generation Intel® Xeon® Scalable Processor Family"]
        elif field_product_name == "Xeon Scalable Gen4":
            new_names = ["4th Generation Intel® Xeon® Scalable Processor Family"]
        elif field_product_name == "Xeon E3/E5, Core X":
            new_names = [
                "Intel® Xeon® Processor E3 Product Family",
                "Intel® Xeon® Processor E5 Product Family",
            ]
        elif field_product_name == "Xeon E5/E7 v4; Core i7-69xx/68xx":
            new_names = [
                "Intel® Xeon® Processor E5v4 Product Family",
                "Intel® Xeon® Processor E7v4 Product Family",
                "Intel® Core™ Processor i7 68xx, 69xx",
            ]
        elif field_product_name == "Xeon E7 v2":
            new_names = [
                "Intel® Xeon® Processor E7v2 Product Family",
            ]
        elif field_product_name == "Xeon E7 v3":
            new_names = [
                "Intel® Xeon® Processor E7v3 Product Family",
            ]
        elif field_product_name == "Xeon D-21xx":
            new_names = [
                "Intel® Xeon® Processor D-21xx",
            ]
        elif field_product_name == "Xeon D-1520/40":
            new_names = [
                "Intel® Xeon® Processor D-1520, D-1540",
            ]
        elif field_product_name == "Xeon D-1557/59/67/71/77/81/87":
            new_names = [
                "Intel® Xeon® Processor D-1557, D-1559, D-1567, D-1571, D-1577, D-1581, D-1587",
            ]
        elif field_product_name == "Xeon D-1513N/23/33/43/53":
            new_names = [
                "Intel® Xeon® Processor D-1513N, D-1523N, D-1533N, D1543N, D1553N",
            ]
        elif field_product_name == "Xeon D-17xx, D-27xx":
            new_names = [
                "Intel® Xeon® Processor D-17xx, D-27xx",
            ]
        elif field_product_name == "Xeon Max":
            new_names = [
                "Intel® Xeon® Max Processor",
            ]
        elif field_product_name == "Xeon Scalable Gen5":
            new_names = [
                "5th Generation Intel® Xeon® Scalable Processor Family",
            ]
        elif matches := re.match(r"^Atom (.*)$", field_product_name):
            new_names = [
                f"Intel® Atom® Processor {matches.group(1).replace(' series', ' Series')}",
            ]
        elif matches := re.match(r"^Core Gen([0-9]+)(.*)$", field_product_name):
            gen_str, modifier = matches.groups()
            generation = int(gen_str)
            gen_th = {
                1: "1st",
                2: "2nd",
                3: "3rd",
            }.get(generation, f"{generation}th")
            if modifier in {"", " Desktop"}:
                new_names = [f"{gen_th} Generation Intel® Core™ Processor Family"]
            elif modifier == " Mobile":
                new_names = [f"{gen_th} Generation Intel® Core™ Mobile Processor Family"]
            elif modifier == " Desktop, Mobile, Xeon E":
                new_names = [
                    f"{gen_th} Generation Intel® Core™ Processor Family",
                    f"{gen_th} Generation Intel® Core™ Mobile Processor Family",
                ]
            elif field_product_name == "Core Gen13/Gen14":
                assert gen_th == "13th"
                new_names = [
                    f"{gen_th} Generation Intel® Core™ Processor Family",
                    "14th Generation Intel® Core™ Processor Family",
                ]
            else:
                raise ValueError(f"Unable to parse Core product name in {line!r}")
        else:
            raise ValueError(f"Unable to parse product name in {line!r}")

        for name in new_names:
            if name not in db_names:
                print(f"Update({cpuid_value:#x}): {cpuid_desc} ({field_acronym}) is {name} ({field_product_name!r})")
                cpuid_db_needs_update = True


def parse_intel_ucode(
    file_data: bytes, ucode_versions: Optional[Set[Tuple[int, int, str]]] = None, verbose: bool = False
) -> bool:
    """Parse Intel Microcode file

    Extract the same information as: iucode-tool -tb -l $FILE

    This is also like https://github.com/platomav/MCExtractor

    Return true if a new microcode was found
    """
    found_new = False
    while file_data:
        if len(file_data) < 0x30:
            raise ValueError(f"Microcode file too small: {len(file_data)}")
        (
            header_type,
            update_rev,
            year,
            day,
            month,
            cpuid,
            _checksum,
            loader_rev,
            platform_id,
            data_size,
            total_size,
            metadata_size,
            update_rev_min,
            reserved_zero,
        ) = struct.unpack("<2IHBB9I", file_data[:0x30])
        if total_size == 0:
            total_size = 2048
        if header_type != 1:
            raise ValueError(f"Unexpected header type in microcode: {header_type}")
        if loader_rev != 1:
            raise ValueError(f"Unexpected loader revision in microcode: {loader_rev}")
        if total_size > len(file_data):
            raise ValueError(f"Unexpected total size in microcode: {total_size} > {len(file_data)}")
        if data_size > total_size:
            raise ValueError(f"Unexpected sizes in microcode: {data_size} > {total_size}")
        if metadata_size not in {0, 0x74}:
            raise ValueError(f"Unexpected metadata in microcode: {metadata_size:#x}")
        if update_rev_min >= update_rev:
            raise ValueError(f"Unexpected minimal update revision in microcode: {update_rev_min}")
        if reserved_zero != 0:
            raise ValueError(f"Unexpected reserved value in microcode: {reserved_zero}")

        # The date is encoded "decimal as hexadecimal"
        date = f"{year:04x}-{month:02x}-{day:02x}"
        if (cpuid, update_rev, date) in KNOWN_INTEL_UCODE_VERSIONS:
            if verbose:
                print(f"  {date}: cpuid {cpuid:#07x} rev {update_rev:#6x} platform {platform_id:#04x} (known)")
        else:
            found_new = True
            print(f"  {date}: cpuid {cpuid:#07x} rev {update_rev:#6x} platform {platform_id:#04x} NEW!")

        if ucode_versions is not None:
            ucode_versions.add((cpuid, update_rev, date))
        file_data = file_data[total_size:]
    return found_new


def parse_intel_ucode_directory(
    directory: Path, ucode_versions: Optional[Set[Tuple[int, int, str]]] = None, verbose: bool = False
) -> None:
    """Parse files present in a clone of Intel-Linux-Processor-Microcode-Data-Files"""
    for releasenote_file in directory.glob("**/releasenote.md"):
        if verbose:
            print(f"Parsing {releasenote_file.absolute()}")
        with releasenote_file.open("r") as stream_text:
            file_text = stream_text.read()
        parse_intel_ucode_releasenote_cfg(file_text)

    for ucode_file in sorted(directory.glob("**/intel-ucode/??-??-??")):
        if verbose:
            print(f"Parsing {ucode_file.absolute()}")
        with ucode_file.open("rb") as stream:
            file_data = stream.read()
        if parse_intel_ucode(file_data, ucode_versions=ucode_versions, verbose=verbose) and not verbose:
            print(f"  ... found in {ucode_file.absolute()}")

    # Parse also directories like the one from https://github.com/platomav/CPUMicrocodes
    for ucode_file in sorted(directory.glob("**/Intel/*.bin")):
        if verbose:
            print(f"Parsing {ucode_file.absolute()}")
        with ucode_file.open("rb") as stream:
            file_data = stream.read()
        if parse_intel_ucode(file_data, ucode_versions=ucode_versions, verbose=verbose) and not verbose:
            print(f"  ... found in {ucode_file.absolute()}")


def parse_intel_ucode_from_github(
    ucode_versions: Optional[Set[Tuple[int, int, str]]] = None, verbose: bool = False
) -> None:
    """Download Intel microcode's main branch and analyze it"""
    if verbose:
        print(f"Downloading {INTEL_UCODE_GIT_MAIN_ZIP_URL}")
    with urllib.request.urlopen(INTEL_UCODE_GIT_MAIN_ZIP_URL) as response:
        zip_data = response.read()
    with zipfile.ZipFile(io.BytesIO(zip_data), "r") as archive:
        for file_info in archive.infolist():
            if file_info.is_dir():
                continue
            if re.match(r"^.*/releasenote\.md$", file_info.filename):
                if verbose:
                    print(f"Parsing {file_info.filename}")
                file_text = archive.read(file_info.filename).decode()
                parse_intel_ucode_releasenote_cfg(file_text)
            if re.match(r"^.*/intel-ucode/[0-9a-f][0-9a-f]-[0-9a-f][0-9a-f]-[0-9a-f][0-9a-f]$", file_info.filename):
                if verbose:
                    print(f"Parsing {file_info.filename}")
                file_data = archive.read(file_info.filename)
                if parse_intel_ucode(file_data, ucode_versions=ucode_versions, verbose=verbose) and not verbose:
                    print(f"  ... found in Intel's {file_info.filename}")


def parse_platomav_intel_microcode_versions_from_github(
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
            if re.match(r"^.*/Intel/.*\.bin$", file_info.filename):
                if verbose:
                    print(f"Parsing {file_info.filename}")
                file_data = archive.read(file_info.filename)
                if parse_intel_ucode(file_data, ucode_versions=ucode_versions, verbose=verbose) and not verbose:
                    print(f"  ... found in Platomav's {file_info.filename}")


def update_intel_microcode_versions(ucode_versions: Set[Tuple[int, int, str]]) -> None:
    """Update intel_microcode_versions.txt with the new microcode version"""
    # Read the file header
    file_header = []
    with INTEL_UCODE_VERSIONS_PATH.open("r") as fin:
        for line in fin:
            if line.startswith("0x"):
                break
            file_header.append(line)
    new_ucode_versions = sorted(KNOWN_INTEL_UCODE_VERSIONS.union(ucode_versions))

    print(f"Updating {INTEL_UCODE_VERSIONS_PATH}")
    with INTEL_UCODE_VERSIONS_PATH.open("w") as fout:
        for line in file_header:
            print(line, file=fout, end="")
        for cpuid, version, date in new_ucode_versions:
            print(f"{cpuid:#07x}  {version:#10x}  {date}", file=fout)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synchronize with Intel microcode releases")
    parser.add_argument(
        "ucode",
        nargs="?",
        type=Path,
        help="directory where https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files is cloned (optional)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    parser.add_argument("-w", "--write", action="store_true", help="update intel_microcode_versions.txt automatically")
    args = parser.parse_args()

    ucode_versions: Set[Tuple[int, int, str]] = set()

    if args.ucode:
        parse_intel_ucode_directory(args.ucode, ucode_versions=ucode_versions, verbose=args.verbose)
    else:
        parse_intel_ucode_from_github(ucode_versions=ucode_versions, verbose=args.verbose)
        parse_platomav_intel_microcode_versions_from_github(ucode_versions=ucode_versions, verbose=args.verbose)

    new_ucode_versions = ucode_versions - KNOWN_INTEL_UCODE_VERSIONS
    if args.verbose or new_ucode_versions:
        print(f"Found {len(ucode_versions)} distinct microcodes, {len(new_ucode_versions)} new")

    if new_ucode_versions and args.write:
        update_intel_microcode_versions(ucode_versions)

    if cpuid_db_needs_update:
        print("The CPUID database needs to be updated.")
        sys.exit(1)
