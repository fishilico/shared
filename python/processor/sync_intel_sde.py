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
"""Extract CPUID information from the files in Intel Software Development Emulator

Intel SDE (Software Development Emulator) provides many CPUID files which can be
used to update the Intel CPUID database

https://www.intel.com/content/www/us/en/developer/articles/tool/software-development-emulator.html
https://www.intel.com/content/www/us/en/download/684897/intel-software-development-emulator.html
    Tested with versions:
        8.69.1
        9.0.0
        9.7.0
        9.14.0
        9.21.1
        9.24.0 from 2023-07-13
        9.27.0 from 2023-09-13
        9.33.0 from 2024-01-07
        9.38.0 from 2024-04-18
        9.44.0 from 2024-08-22
        9.48.0 from 2024-11-25

"""
import argparse
import re
import struct
from pathlib import Path
from typing import Dict, FrozenSet, List, Tuple

from cpu_model import CPU_MODELS, X86CPUInfo

# Known associations between acronym_from_map in SDE path and acronym_from_map in the database
KNOWN_SDE_ACRONYM: FrozenSet[Tuple[int, str, str]] = frozenset(
    (
        # Version 8.69.1 may confuse Broadwell and Haswell
        (0x306C1, "bdw", "HSW"),
        # Version 8.69.1 defines 0x50650 as Cooper Lake X (which starts at stepping 10) instead of Skylake X
        (0x50650, "cpx", "SKX"),
        # Version 8.69.1 defines 0x50654 as Cascade Lake X (which starts at stepping 5) instead of Skylake X
        (0x50654, "clx", "SKX-SP/D"),
        # Version 8.69.1 defines 0x50670 (Xeon Phi Knights Landing) without "Phi"
        (0x50670, "knl", "PHI KNL"),
        # Version 8.69.1 defines 0x506c2 as Goldmont, which is the microarchitecture of Broxton
        (0x506C2, "glm", "BXT"),
        # Version 8.69.1 defines 0x506c2 as Goldmont Plus, which is the microarchitecture of Broxton
        (0x506C2, "glp", "BXT"),
        # Version 8.69.1 defines 0x80650 (Xeon Phi Knights Mill) without "Phi"
        (0x80650, "knm", "PHI KNM"),
        # Version 8.69.1 defines 0x806f0 as "future"
        (0x806F0, "future", "SPR-SP"),
        # Version 9.14.0 defines 0x90660 as Grand Ridge instead of Elkhart Lake
        (0x90660, "grr", "EHL"),
        # Version 8.69.1 defines 0x90660 as Snow Ridge instead of Elkhart Lake (both based on Tremont)
        (0x90660, "snr", "EHL"),
        # Version 9.14.0 defines 0x90660 as Sierra Forest instead of Elkhart Lake
        (0x90660, "srf", "EHL"),
        # Version 8.69.1 defines 0x90660 as Tremont, which is the microarchitecture of Elkhart Lake
        (0x90660, "tnt", "EHL"),
        # Version 9.33.0 uses "GNR 256"
        (0xA06D0, "gnr256", "GNR-X"),
    )
)

PENTIUM3_BRAND_STRING = bytes.fromhex("0101020300000000000000008208040c") * 3


def parse_sde_directory(sde_path: Path, verbose: bool = False) -> None:
    """Parse CPUID files from Intel SDE"""
    for cpuid_file in sorted(sde_path.glob("misc/cpuid/**/*")):
        if cpuid_file.is_dir():
            continue
        relative_path = cpuid_file.relative_to(sde_path)
        if verbose:
            print(f"  {relative_path}")
        matches = re.match(r"^misc/cpuid/([a-z0-9-]+)/cpuid\.def$", str(relative_path))
        if not matches:
            raise ValueError(f"Unexpected file name {relative_path!r}")
        path_acronym = matches.group(1)
        if path_acronym == "icl-server":
            # Remove the suffix
            path_acronym = path_acronym.split("-", 1)[0]

        # Read the CPUID file
        cpuid_values: Dict[Tuple[int, int], List[int]] = {}
        with cpuid_file.open("r") as fd:
            for line in fd:
                line = line.rstrip()

                # Parse lines such as "00000001 ******** => 000206c2 00200800 029a2203 1f8bfbff"
                matches = re.match(
                    r"^([0-9a-f]{8}) ([0-9a-f*]{8}) => ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8})$", line
                )
                if matches:
                    parts: List[int] = [-1 if x == "********" else int(x, 16) for x in matches.groups()]
                    cpuid_eax = parts.pop(0)
                    cpuid_ecx = parts.pop(0)
                    key = (cpuid_eax, cpuid_ecx)
                    if key in cpuid_values:
                        raise ValueError(
                            f"Unexpected duplicate CPUID entry for {cpuid_eax:#x},{cpuid_ecx:#x} in {cpuid_file!r}"
                        )
                    cpuid_values[key] = parts

        cpuid_0 = cpuid_values.get((0, -1))
        if cpuid_0 is None:
            raise ValueError(f"Missing CPUID[0] value in {cpuid_file!r}")
        vendor_string = struct.pack("<3I", cpuid_0[1], cpuid_0[3], cpuid_0[2])
        if vendor_string != b"GenuineIntel":
            raise ValueError(f"Unexpected vendor string {vendor_string!r} in CPUID[0] in {cpuid_file!r}")

        cpuid_1 = cpuid_values.get((1, -1))
        if cpuid_1 is None:
            raise ValueError(f"Missing CPUID[1] value in {cpuid_file!r}")
        cpuid_value = cpuid_1[0]

        brand_string_bytes = b""
        for cpuid_eax in (0x80000002, 0x80000003, 0x80000004):
            try:
                values = cpuid_values[(cpuid_eax, -1)]
            except KeyError:
                continue
            brand_string_bytes += struct.pack("<4I", values[0], values[1], values[2], values[3])
        brand_string_bytes = brand_string_bytes.strip(b"\0").strip(b" ")

        if brand_string_bytes == PENTIUM3_BRAND_STRING:
            # Ignore pentium 3 brand string
            brand_string_bytes = b""
        elif brand_string_bytes in {b"Genuine Intel(R) 0000", b"Genuine Intel(R) CPU 0000%@"}:
            # Ignore generic brand string
            brand_string_bytes = b""
        brand_string = brand_string_bytes.decode("ascii")

        # Compare with the database
        cpuinfo = X86CPUInfo("GenuineIntel", None, cpuid_value)
        cpu_models = CPU_MODELS.get(cpuinfo.vendor_id, {}).get(cpuinfo.x86_family)
        if cpu_models is None:
            print(f"Warning({cpuid_value:#x}): unknown Intel family {cpuinfo.x86_family}")
            model_data = None
        else:
            model_data = cpu_models.get((cpuinfo.x86_model, cpuinfo.x86_stepping))

        if model_data is None:
            # Missing CPUID
            print(
                f"Update({cpuid_value:#x}): Unknown model/stepping {cpuinfo.x86_model:#x}, {cpuinfo.x86_stepping} for {path_acronym}"  # noqa
            )
        else:
            acronym = model_data.acronym
            if acronym is None:
                if path_acronym not in {"pentium3", "pentium4", "pentium4p", "quark"}:
                    print(
                        f"Update({cpuid_value:#x}): CPUID model/stepping {cpuinfo.x86_model:#x}, {cpuinfo.x86_stepping} uses path acronym {path_acronym}"  # noqa
                    )
            elif (
                path_acronym != acronym.split("-", 1)[0].lower()
                and (cpuid_value, path_acronym, acronym) not in KNOWN_SDE_ACRONYM
            ):
                print(
                    f"Warning({cpuid_value:#x}): missing acronym_from_map association in known list ({cpuid_value:#07x}, {path_acronym!r}, {acronym!r})"  # noqa
                )

            if brand_string and brand_string not in model_data.desc_list:
                print(f"Update({cpuid_value:#x}): missing brand string: {brand_string}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synchronize with Intel SDE files")
    parser.add_argument(
        "sde",
        nargs="+",
        type=Path,
        help="directory where Intel SDE for Linux has been extracted",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    args = parser.parse_args()

    for sde_path in args.sde:
        if args.verbose:
            print(f"Browsing {sde_path}")
        parse_sde_directory(sde_path, verbose=args.verbose)
