#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2018 Nicolas Iooss
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
"""Find the CPU model of the current processor

CPU Microcode repository: https://github.com/platomav/CPUMicrocodes
"""
from __future__ import unicode_literals

import argparse
import ctypes
import ctypes.util
import logging
import os.path
import platform
import re
import struct
import sys

try:
    from typing import Callable, Dict, List, Optional, Sequence, Tuple, Type, Union
except ImportError:
    pass


logger = logging.getLogger(__name__)


class CpuidInformation:
    """Information about a cpuid value, used as a leaf of CPU_MODELS"""

    def __init__(self, acronym, main_desc):  # type: (CpuidInformation, Optional[str], str) -> None
        self.acronym = acronym
        self.main_desc = main_desc
        self.desc_list = []  # type: List[str]


def load_x86_cpuid(filename):  # type: (str) -> Dict[int, Dict[Tuple[int, int], CpuidInformation]]
    """Load amd_x86_cpuid.txt and intel_x86_cpuid.txt"""
    models_by_family = {}  # type: Dict[int, Dict[Tuple[int, int], CpuidInformation]]
    current_family = None  # type: Optional[int]
    last_model_stepping = None  # type: Optional[Tuple[int, int]]
    with open(os.path.join(os.path.dirname(__file__), filename), "rb") as fmicrocode:
        for raw_line in fmicrocode:
            if b"\t" in raw_line:
                raise ValueError("Invalid line: tabulation is present in {}".format(repr(raw_line)))

            line = raw_line.decode("utf-8").rstrip()
            if not line or line.startswith("#"):
                continue

            # Start family definitions with "[Family 6]"
            matches = re.match(r"^\[Family ([0-9]+)\]$", line)
            if matches:
                current_family = int(matches.group(1))
                models_by_family[current_family] = {}
                last_model_stepping = None
                continue

            # Start family definitions with hexadecimal such as "[Family 25] # Family 19h"
            matches = re.match(r"^\[Family ([0-9]+)\] # Family ([0-9a-f]+)h$", line)
            if matches:
                current_family = int(matches.group(1))
                current_family_bis = int(matches.group(2), 16)
                if current_family != current_family_bis:
                    raise ValueError("Mismatched family numbers in {}".format(repr(line)))
                models_by_family[current_family] = {}
                last_model_stepping = None
                continue

            if current_family is None:
                raise ValueError("Invalid line: no family defined before {}".format(repr(line)))

            matches = re.match(r"^0x([0-9a-f][0-9a-f]), +([0-9]+|x) \(0x([0-9a-f]{4,5}[0-9a-fx])\): (.*)$", line)
            if matches:
                model_str, stepping_str, cpuid_str, main_desc = matches.groups()
                model = int(model_str, 16)
                if filename == "amd_x86_cpuid.txt":
                    if len(cpuid_str) != 6:
                        raise ValueError("Invalid line: CPUID value not of the expected length {} in {}".format(repr(line), filename))
                elif filename == "intel_x86_cpuid.txt":
                    if len(cpuid_str) not in {5, 6}:
                        raise ValueError("Invalid line: CPUID value not of the expected length {} in {}".format(repr(line), filename))
                else:
                    raise NotImplementedError("Unknown file name {}".format(filename))
                if stepping_str == "x":
                    stepping = -1
                    if not cpuid_str.endswith("x"):
                        raise ValueError("Invalid line: 'x' stepping but full cpuid in {}".format(repr(line)))
                    cpuid = int(cpuid_str[:-1], 16) << 4
                else:
                    stepping = int(stepping_str, 10)
                    cpuid = int(cpuid_str, 16)

                expected_cpuid = X86CPUInfo.encode_cpuid(current_family, model, stepping if stepping != -1 else 0)
                if cpuid != expected_cpuid:
                    raise ValueError(
                        "Invalid line: expected CPUID {:#x} != {:#x} in {}".format(expected_cpuid, cpuid, repr(line))
                    )

                acronym = None
                if main_desc.startswith('"'):
                    # Extract acronym
                    matches = re.match(r'^"([0-9A-Ze /-]+)" (.*)$', main_desc)
                    if not matches:
                        raise ValueError("Invalid line: unexpected acronym format in {}".format(repr(line)))
                    acronym, main_desc = matches.groups()

                if main_desc.startswith(" "):
                    raise ValueError("Invalid line: desc starts with space {}".format(repr(line)))

                if last_model_stepping is not None and last_model_stepping >= (model, stepping):
                    raise ValueError(
                        "Line out of order after ({:#x}, {}): {}".format(
                            last_model_stepping[0], last_model_stepping[1], repr(line)
                        )
                    )
                last_model_stepping = (model, stepping)
                if last_model_stepping in models_by_family[current_family]:
                    raise ValueError("Invalid line: duplicate model, stepping in {}".format(repr(line)))
                models_by_family[current_family][last_model_stepping] = CpuidInformation(acronym, main_desc)
                continue

            if last_model_stepping is not None and line.startswith("    "):
                desc = line[4:]
                if desc.startswith(" "):
                    raise ValueError("Invalid line: too many leading spaces in {}".format(repr(line)))
                models_by_family[current_family][last_model_stepping].desc_list.append(desc)
                continue

            raise ValueError("Invalid line: failed to match any known pattern {}".format(repr(line)))

    return models_by_family


def load_x86_microcode_versions(filename):  # type: (str) -> List[Tuple[int, int, str]]
    """Load amd_microcode_versions.txt or intel_microcode_versions.txt"""
    versions = []
    with open(os.path.join(os.path.dirname(__file__), filename), "r") as fmicrocode:
        for line in fmicrocode:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            matches = re.match(r"^0x([0-9a-f]+) +0x([0-9a-f]+) +([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])$", line)
            if not matches:
                raise ValueError("Invalid line in intel_microcode_versions.txt: {}".format(repr(line)))
            cpuid_str, version_str, date = matches.groups()
            versions.append((int(cpuid_str, 16), int(version_str, 16), date))
    return versions


AMD_UCODE_VERSIONS = load_x86_microcode_versions("amd_microcode_versions.txt")
INTEL_UCODE_VERSIONS = load_x86_microcode_versions("intel_microcode_versions.txt")

# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/include/asm/cputype.h
# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/kernel/cpuinfo.c
# https://github.com/util-linux/util-linux/blob/master/sys-utils/lscpu-arm.c
AARCH64_PARTS = {
    0x41: (  # 'A'
        "ARM Limited",
        {
            0x000: "Potenza",
            0x810: "ARM810",
            0x920: "ARM920",
            0x922: "ARM922",
            0x926: "ARM926",
            0x940: "ARM940",
            0x946: "ARM946",
            0x966: "ARM966",
            0xA20: "ARM1020",
            0xA22: "ARM1022",
            0xA26: "ARM1026",
            0xB02: "ARM11 MPCore",
            0xB36: "ARM1136",
            0xB56: "ARM1156",
            0xB76: "ARM1176",
            0xC05: "Cortex-A5",
            0xC07: "Cortex-A7",
            0xC08: "Cortex-A8",
            0xC09: "Cortex-A9",
            0xC0D: "Cortex-A17",  # Originally A12
            0xC0F: "Cortex-A15",
            0xC0E: "Cortex-A17",
            0xC14: "Cortex-R4",
            0xC15: "Cortex-R5",
            0xC17: "Cortex-R7",
            0xC18: "Cortex-R8",
            0xC20: "Cortex-M0",
            0xC21: "Cortex-M1",
            0xC23: "Cortex-M3",
            0xC24: "Cortex-M4",
            0xC27: "Cortex-M7",
            0xC60: "Cortex-M0+",
            0xD00: "Foundation",
            0xD01: "Cortex-A32",
            0xD02: "Cortex-A34",
            0xD03: "Cortex-A53",
            0xD04: "Cortex-A35",
            0xD05: "Cortex-A55",
            0xD06: "Cortex-A65",
            0xD07: "Cortex-A57",
            0xD08: "Cortex-A72",
            0xD09: "Cortex-A73",
            0xD0A: "Cortex-A75",
            0xD0B: "Cortex-A76",
            0xD0C: "Neoverse-N1",
            0xD0D: "Cortex-A77",
            0xD0E: "Cortex-A76AE",
            0xD0F: "AEM-v8",
            0xD13: "Cortex-R52",
            0xD15: "Cortex-R82",
            0xD20: "Cortex-M23",
            0xD21: "Cortex-M33",
            0xD40: "Neoverse-V1",
            0xD41: "Cortex-A78",
            0xD42: "Cortex-A78AE",
            0xD43: "Cortex-A65AE",
            0xD44: "Cortex-X1",
            0xD46: "Cortex-A510",
            0xD47: "Cortex-A710",
            0xD48: "Cortex-X2",
            0xD49: "Neoverse-N2",
            0xD4A: "Neoverse-E1",
            0xD4B: "Cortex-A78C",
            0xD4C: "Cortex-X1C",
            0xD4D: "Cortex-A715",
            0xD4E: "Cortex-X3",
            0xD4F: "Neoverse-V2",
        },
    ),
    0x42: (  # 'B'
        "Broadcom",
        {
            0x00F: "Brahma-B15",
            0x100: "Brahma B53",
            0x516: "Vulcan",  # "ThunderX2" in util-linux lscpu-arm
        },
    ),
    0x43: (  # 'C'
        "Cavium",
        {
            0x0A0: "ThunderX",
            0x0A1: "ThunderX-88XX",
            0x0A2: "ThunderX 81XX",
            0x0A3: "ThunderX 83XX",
            0x0AF: "ThunderX2-99xx",
            0x0B0: "OcteonTX2",
            0x0B1: "OcteonTX2-98XX",
            0x0B2: "OcteonTX2-96XX",
            0x0B3: "OcteonTX2-95XX",
            0x0B4: "OcteonTX2-95XXN",
            0x0B5: "OcteonTX2-95XXMM",
            0x0B6: "OcteonTX2-95XXO",
            0x0B8: "ThunderX3-T110",
        },
    ),
    0x44: (  # 'D'
        "DEC",
        {
            0xA10: "SA110",
            0xA11: "SA1100",
        },
    ),
    0x46: (  # 'F'
        "Fujitsu",
        {
            0x001: "A64FX",
        },
    ),
    0x48: (  # 'H'
        "HiSilicon",
        {
            0xD01: "TSV110, Kunpeng-920",
            0xD40: "Cortex-A76",
        },
    ),
    0x49: ("Infineon", {}),  # 'I'
    0x4D: ("Motorola/Freescale", {}),  # 'M'
    0x4E: (
        "NVidia",  # 'N'
        {
            0x000: "Denver",
            0x003: "Denver 2",
            0x004: "Carmel",
        },
    ),
    0x50: (  # 'P'
        "Applied Micro (APM)",
        {
            0x000: "Potenza",  # "X-Gene" in util-linux lscpu-arm
        },
    ),
    0x51: (  # 'Q'
        "Qualcomm",
        {
            0x00F: "Scorpion",
            0x02D: "Scorpion",
            0x04D: "Krait",
            0x06F: "Krait",
            0x200: "Kryo",
            0x201: "Kryo",
            0x205: "Kryo",
            0x211: "Kryo",
            0x800: "Falkor v1, Kryo 2XX Gold",
            0x801: "Kryo 2XX Silver",
            0x803: "Kryo 3XX Silver",
            0x804: "Kryo 4XX Gold",
            0x805: "Kryo 4XX Silver",
            0xC00: "Falkor",
            0xC01: "Saphira",
        },
    ),
    0x53: (  # 'S'
        "Samsung",
        {
            0x001: "exynos-m1",
            0x002: "exynos-m3",
            0x003: "exynos-m4",
            0x004: "exynos-m5",
        },
    ),
    0x56: (  # 'V'
        "Marvell",
        {
            0x131: "Feroceon-88FR131",
            0x581: "PJ4/PJ4b",
            0x584: "PJ4B-MP",
        },
    ),
    0x61: (  # 'a'
        "Apple",
        {
            0x000: "Swift",
            0x001: "Cyclone",
            0x002: "Typhoon",
            0x003: "Typhoon/Capri",
            0x004: "Twister",
            0x005: "Twister/Elba/Malta",
            0x006: "Hurricane",
            0x007: "Hurricane/Myst",
            0x008: "Monsoon",
            0x009: "Mistral",
            0x00B: "Vortex",
            0x00C: "Tempest",
            0x00F: "Tempest-M9",
            0x010: "Vortex/Aruba",
            0x011: "Tempest/Aruba",
            0x012: "Lightning",
            0x013: "Thunder",
            0x020: "Icestorm-A14",
            0x021: "Firestorm-A14",
            0x022: "M1 Icestorm",
            0x023: "M1 Firestorm",
            0x024: "M1 Icestorm Pro",
            0x025: "M1 Firestorm Pro",
            0x026: "Thunder-M10",
            0x028: "M1 Icestorm Max",
            0x029: "M1 Firestorm Max",
            0x030: "Blizzard-A15",
            0x031: "Avalanche-A15",
            0x032: "M2 Blizzard",
            0x033: "M2 Avalanche",
            0x034: "M2 Blizzard Pro",
            0x035: "M2 Avalanche Pro",
            0x036: "Sawtooth-A16",
            0x037: "Everest-A16",
            0x038: "M2 Blizzard Max",
            0x039: "M2 Avalanche Max",
        },
    ),
    0x66: (  # 'f'
        "Faraday",
        {
            0x526: "FA526",
            0x626: "FA626",
        },
    ),
    0x69: (  # 'i'
        "Intel",
        {
            0x200: "i80200",
            0x210: "PXA250A",
            0x212: "PXA210A",
            0x242: "i80321-400",
            0x243: "i80321-600",
            0x290: "PXA250B/PXA26x",
            0x292: "PXA210B",
            0x2C2: "i80321-400-B0",
            0x2C3: "i80321-600-B0",
            0x2D0: "PXA250C/PXA255/PXA26x",
            0x2D2: "PXA210C",
            0x411: "PXA27x",
            0x41C: "IPX425-533",
            0x41D: "IPX425-400",
            0x41F: "IPX425-266",
            0x682: "PXA32x",
            0x683: "PXA930/PXA935",
            0x688: "PXA30x",
            0x689: "PXA31x",
            0xB11: "SA1110",
            0xC12: "IPX1200",
        },
    ),
    0x70: (  # 'p'
        "Phytium",
        {
            0x660: "FTC660",
            0x661: "FTC661",
            0x662: "FTC662",
            0x663: "FTC663",
        },
    ),
    0xC0: (
        "Ampere",
        {
            0xAC3: "Ampere 1",
            0xAC4: "Ampere-1a",
        },
    ),
}  # type: Dict[int, Tuple[str, Dict[int, str]]]


class CPUInfo(object):
    """Information about a CPU"""

    def __init__(self, architecture):  # type: (CPUInfo, str) -> None
        self.architecture = architecture

    @staticmethod
    def decode_cpuinfo(filename=None):  # type: (Optional[str]) -> Union[None, Aarch64CPUInfo, X86CPUInfo]
        """Build a CPUInfo object from /proc/cpuinfo content"""
        field_names = set(
            (
                # x86
                "vendor_id",
                "cpu family",
                "model",
                "model name",
                "stepping",
                "microcode",
                # aarch64
                "CPU implementer",
                "CPU architecture",
                "CPU variant",
                "CPU part",
                "CPU revision",
            )
        )
        fields = {}  # type: Dict[str, Union[int, str]]
        if filename is None:
            filename = "/proc/cpuinfo"
            if not os.path.exists(filename):
                logger.debug("%s does not exist, skipping it", filename)
                return None

        logger.debug("Reading %r", filename)
        with open(filename, "r") as cpuinfo_file:
            for line in cpuinfo_file:
                if ":" in line:
                    key, value_str = line.split(":", 1)
                    key = key.strip()
                    value_str = value_str.strip()
                    if key in field_names:
                        # Decode the value if it is an int
                        if re.match(r"^[0-9]+$", value_str):
                            value = int(value_str)  # type: Union[int, str]
                        elif re.match(r"^0x[0-9a-fA-F]+$", value_str):
                            value = int(value_str[2:], 16)
                        else:
                            value = value_str
                        cur_value = fields.get(key)
                        if cur_value is None:
                            fields[key] = value
                        elif cur_value != value:
                            logger.error("CPU with different information: %s is %r and %r", key, cur_value, value)

        vendor_id = fields.get("vendor_id")
        model_name = fields.get("model name")
        microcode_version = fields.get("microcode")
        if vendor_id is not None and model_name is not None:
            # Do not use isinstance(..., str) because in Python 2, they are unicode strings
            assert not isinstance(vendor_id, int)
            assert not isinstance(model_name, int)
            assert isinstance(microcode_version, int)
            cpuid = None
            family = fields.get("cpu family")
            assert isinstance(family, int)
            model = fields.get("model")
            assert isinstance(model, int)
            stepping = fields.get("stepping")
            assert isinstance(stepping, int)
            if family is not None and model is not None and stepping is not None:
                cpuid = X86CPUInfo.encode_cpuid(family, model, stepping)
            else:
                logger.error("CPUID components not found in %s", filename)
                return

            return X86CPUInfo(vendor_id, model_name, cpuid, microcode_version)

        implementer = fields.get("CPU implementer")
        architecture = fields.get("CPU architecture")
        if implementer is not None and architecture is not None:
            assert isinstance(implementer, int)
            assert not isinstance(architecture, int)
            variant = fields.get("CPU variant")
            assert isinstance(variant, int)
            part = fields.get("CPU part")
            assert isinstance(part, int)
            revision = fields.get("CPU revision")
            assert isinstance(revision, int)
            return Aarch64CPUInfo(implementer, architecture, variant, part, revision)

        logger.error("Unable to find key fields in %s (vendor_id, CPU implementer, etc.)", filename)
        return None



class Aarch64CPUInfo(CPUInfo):
    """Information about an Aarch64 (ARM64) CPU from MIDR_EL1 register

    MIDR: Main ID Register
        ARM64: MRS <Xt>, MIDR_EL1
        ARM32: MRC p15, 0, <Rt>, c0, c0, 0

    It is also accessible from
    /sys/devices/system/cpu/cpu0/regs/identification/midr_el1
    """

    def __init__(
        self, implementer, architecture, variant, part, revision
    ):  # type: (Aarch64CPUInfo, int, str, int, int, int) -> None
        super(Aarch64CPUInfo, self).__init__("aarch64")
        self.implementer = implementer
        self.architecture = architecture
        self.variant = variant
        self.part = part
        self.revision = revision

    def unique_key(self):  # type: (Aarch64CPUInfo) -> Tuple[str, int, str, int, int, int]
        """Get a unique key representing the CPU"""
        return self.architecture, self.implementer, self.architecture, self.variant, self.part, self.revision

    def __repr__(self):  # type: (Aarch64CPUInfo) -> str
        return "{}({}, {}, {}, {}, {})".format(
            self.__class__.__name__,
            hex(self.implementer),
            self.architecture,
            hex(self.variant),
            hex(self.part),
            hex(self.revision),
        )

    def describe(self):  # type: (Aarch64CPUInfo) -> None
        impl_data = AARCH64_PARTS.get(self.implementer)
        if impl_data is not None:
            impl_name, impl_parts = impl_data
        else:
            impl_name = "?"
            impl_parts = {}

        print("- Implementer: {} ({:#x})".format(impl_name, self.implementer))
        print("- Part: {} ({:#x})".format(impl_parts.get(self.part, "?"), self.part))
        print("- Architecture: {}".format(self.architecture))
        print("- Variant: {:#x}".format(self.variant))
        print("- Revision: {}".format(self.revision))


class X86CPUInfo(CPUInfo):
    """Information about an x86 CPU

    CPUID[EAX=0].(EBX,ECX,EDX) contains the vendor ID
    CPUID[EAX=1].EAX contains version information (Type, Family, Model, and Stepping ID)
        bits  0- 3 Stepping ID
        bits  4- 7 Model
        bits  8-11 Family ID (for example: 6 or 0xf)
        bits 12-13 Processor Type
                    (in practice: 0 (Original OEM Processor)
                    or 1 (Intel OverDrive, only found for CPUID 0x00001632))
        bits 14-15 Reserved
        bits 16-19 Extended Model ID
        bits 20-27 Extended Family ID (in practice: 0 for Intel)
        bits 28-31 Reserved
    CPUID[EAX=0x80000002,0x80000003,0x80000004] contains the Processor Brand String
    """

    def __init__(
        self, vendor_id, model_name, cpuid, microcode_version=None
    ):  # type: (X86CPUInfo, str, Optional[str], int, Optional[int]) -> None
        super(X86CPUInfo, self).__init__("x86")
        self.vendor_id = vendor_id
        self.model_name = model_name
        self.cpuid = cpuid
        self.microcode_version = microcode_version

    def unique_key(self):  # type: (X86CPUInfo) -> Tuple[str, str, Optional[str], int]
        """Get a unique key representing the CPU"""
        return self.architecture, self.vendor_id, self.model_name, self.cpuid

    def __repr__(self):  # type: (X86CPUInfo) -> str
        return "{}({}, {}, {}, {})".format(
            self.__class__.__name__,
            repr(self.vendor_id),
            repr(self.model_name),
            hex(self.cpuid),
            hex(self.microcode_version) if self.microcode_version is not None else "None",
        )

    @staticmethod
    def encode_cpuid(family, model, stepping):  # type: (int, int, int) -> int
        """Encode the CPUID of x86 CPU"""
        assert 0 <= family <= 0xFF + 0xF
        assert 0 <= model <= 0xFF
        assert 0 <= stepping <= 0xF

        if family <= 0xF:
            base_family = family
            extended_family = 0
        else:
            base_family = 0xF
            extended_family = family - 0xF

        return (extended_family << 20) | ((model & 0xF0) << 12) | (base_family << 8) | ((model & 0xF) << 4) | stepping

    @property
    def x86_family(self):  # type: (X86CPUInfo) -> int
        """Returns the family identifier, encoded in bits 8-11 and 20-27"""
        return ((self.cpuid >> 8) & 0xF) + ((self.cpuid >> 20) & 0xFF)

    @property
    def x86_model(self):  # type: (X86CPUInfo) -> int
        """Returns the model number, encoded in bits 4-7 and 16-19"""
        return ((self.cpuid >> 4) & 0xF) + ((self.cpuid >> 12) & 0xF0)

    @property
    def x86_stepping(self):  # type: (X86CPUInfo) -> int
        return self.cpuid & 0xF

    def desc_cpuid(self):  # type: (X86CPUInfo) -> List[str]
        """Describe the cpuid signature in a list of strings"""
        lines = [
            "{0:#x} (family {1:d} model {2:d}={2:#x} stepping {3:d})".format(
                self.cpuid, self.x86_family, self.x86_model, self.x86_stepping
            )
        ]
        cpu_models = CPU_MODELS.get(self.vendor_id, {}).get(self.x86_family)
        if cpu_models is not None:
            cpuid_data = cpu_models.get((self.x86_model, self.x86_stepping))
            if cpuid_data is None:
                cpuid_data = cpu_models.get((self.x86_model, -1))
            if cpuid_data is None:
                logger.warning(
                    "Unknown CPU family %d model %#x stepping %d", self.x86_family, self.x86_model, self.x86_stepping
                )
            else:
                second_line = cpuid_data.main_desc
                if cpuid_data.acronym is not None:
                    second_line = '"{}" {}'.format(cpuid_data.acronym, second_line)
                lines.append(second_line)
                for desc in cpuid_data.desc_list:
                    lines.append("    {}".format(desc))
        return lines

    def desc_microcode_version(self):  # type: (X86CPUInfo) -> List[str]
        """Describe the microcode version in a list of strings"""
        if self.microcode_version is None:
            return ["unknown"]
        microcode_list = []  # type: List[Tuple[int, str]]
        version_date = None  # type: Optional[str]
        available_upgrade_ver = None  # type: Optional[int]
        available_upgrade_date = None  # type: Optional[str]
        if self.vendor_id == "AuthenticAMD":
            ucode_versions = AMD_UCODE_VERSIONS
        elif self.vendor_id == "GenuineIntel":
            ucode_versions = INTEL_UCODE_VERSIONS
        else:
            ucode_versions = None
        if ucode_versions:
            for known_cpuid, known_ver, update_date in ucode_versions:
                if known_cpuid != self.cpuid:
                    continue
                microcode_list.append((known_ver, update_date))
                if self.microcode_version == known_ver:
                    version_date = update_date
                elif self.microcode_version < known_ver:
                    if available_upgrade_ver is None or available_upgrade_ver < known_ver:
                        available_upgrade_ver = known_ver
                        available_upgrade_date = update_date

        desc = "{:#x}".format(self.microcode_version)
        if version_date:
            desc += " from {}".format(version_date)
        lines = [desc]
        if available_upgrade_date and available_upgrade_date != version_date:
            assert available_upgrade_ver is not None
            lines.append("Available upgrade {:#x} from {}".format(available_upgrade_ver, available_upgrade_date))
        if microcode_list:
            microcode_list.sort()
            lines.append("Known microcode versions:")
            is_current_present = False
            for known_ver, update_date in microcode_list:
                if not is_current_present and known_ver > self.microcode_version:
                    lines.append("    ({:#x} - current)".format(self.microcode_version))
                    is_current_present = True
                lines.append("    {:#x} from {}".format(known_ver, update_date))
                if self.microcode_version == known_ver:
                    lines[-1] += " (current)"
                    is_current_present = True
            if not is_current_present:
                # The list of known microcode is outdated
                logger.warning("Current microcode version is newer than known ones")
        return lines

    def describe(self):  # type: (X86CPUInfo) -> None
        print("- Vendor ID: {}".format(self.vendor_id))
        print("- Model name: {}".format(self.model_name))
        cpuid_lines = self.desc_cpuid()
        print("- CPUID: {}".format(cpuid_lines[0]))
        for line in cpuid_lines[1:]:
            print("    {}".format(line))
        microcode_lines = self.desc_microcode_version()
        print("- Microcode version: {}".format(microcode_lines[0]))
        for line in microcode_lines[1:]:
            print("    {}".format(line))

    @classmethod
    def decode_x86_cpuid(cls):  # type: (Type[X86CPUInfo]) -> Optional[X86CPUInfo]
        """Run cpuid if on x86 to get the relevant CPUInfo"""
        plat_mach = platform.machine()
        plat_sys = platform.system()
        if plat_mach in ("AMD64", "x86_64"):
            ptrsize = 64
        elif plat_mach in ("x86", "i686"):
            ptrsize = 32
        else:
            logger.warning("Not using x86 cpuid instruction on %s", platform.machine())
            return None

        if ptrsize != ctypes.sizeof(ctypes.c_void_p) * 8:
            logger.error(
                "platform.machine() %r is inconsistent with sizeof(void*) = %d",
                plat_mach,
                ctypes.sizeof(ctypes.c_void_p),
            )
            return None

        # Find a assembly function which performs:
        # void do_cpuid(uint32_t regs[4]) // regs are eax, ebx, ecx, edx
        # {
        #     __asm__ volatile ("cpuid"
        #         :"=a"(regs[0]), "=b"(regs[1]), "=c"(regs[2]), "=d"(regs[3])
        #         :"0"(regs[0]), "1"(regs[1]), "2"(regs[2]), "3"(regs[3]));
        # }
        cpuid_functions = {
            "cdecl.x86_32":
            # Arg on stack, ebx as PIC register, esi preserved
            #  0:  56               push   %esi
            #  1:  53               push   %ebx
            #  2:  8b 74 24 0c      mov    0xc(%esp),%esi
            #  6:  8b 06            mov    (%esi),%eax
            #  8:  8b 5e 04         mov    0x4(%esi),%ebx
            #  b:  8b 4e 08         mov    0x8(%esi),%ecx
            #  e:  8b 56 0c         mov    0xc(%esi),%edx
            # 11:  0f a2            cpuid
            # 13:  89 06            mov    %eax,(%esi)
            # 15:  89 5e 04         mov    %ebx,0x4(%esi)
            # 18:  89 4e 08         mov    %ecx,0x8(%esi)
            # 1b:  89 56 0c         mov    %edx,0xc(%esi)
            # 1e:  5b               pop    %ebx
            # 1f:  5e               pop    %esi
            # 20:  c3               ret
            b"VS\x8bt$\x0c\x8b\x06\x8b^\x04\x8bN\x08\x8bV\x0c\x0f\xa2\x89\x06\x89^\x04\x89N\x08\x89V\x0c[^\xc3",
            "Linux.x86_64":
            # Arg is rdi, rbx preserved
            #  0:  53               push   %rbx
            #  1:  8b 07            mov    (%rdi),%eax
            #  3:  8b 5f 04         mov    0x4(%rdi),%ebx
            #  6:  8b 4f 08         mov    0x8(%rdi),%ecx
            #  9:  8b 57 0c         mov    0xc(%rdi),%edx
            #  c:  0f a2            cpuid
            #  e:  89 5f 04         mov    %ebx,0x4(%rdi)
            # 11:  89 07            mov    %eax,(%rdi)
            # 13:  89 4f 08         mov    %ecx,0x8(%rdi)
            # 16:  89 57 0c         mov    %edx,0xc(%rdi)
            # 19:  5b               pop    %rbx
            # 1a:  c3               retq
            b"S\x8b\x07\x8b_\x04\x8bO\x08\x8bW\x0c\x0f\xa2\x89_\x04\x89\x07\x89O\x08\x89W\x0c[\xc3",
            "Windows.x86_64":
            # Args is rcx, rbx preserved
            #  0: 53                push   %rbx
            #  1: 8b 01             mov    (%rcx),%eax
            #  3: 8b 59 04          mov    0x4(%rcx),%ebx
            #  6: 49 89 c8          mov    %rcx,%r8
            #  9: 8b 49 08          mov    0x8(%rcx),%ecx
            #  c: 41 8b 50 0c       mov    0xc(%r8),%edx
            # 10: 0f a2             cpuid
            # 12: 41 89 00          mov    %eax,(%r8)
            # 15: 41 89 58 04       mov    %ebx,0x4(%r8)
            # 19: 41 89 48 08       mov    %ecx,0x8(%r8)
            # 1d: 41 89 50 0c       mov    %edx,0xc(%r8)
            # 21: 5b                pop    %rbx
            # 22: c3                retq
            b"S\x8b\x01\x8bY\x04I\x89\xc8\x8bI\x08A\x8bP\x0c\x0f\xa2A\x89\x00A\x89X\x04A\x89H\x08A\x89P\x0c[\xc3",
        }
        cpuid_functions_map = {
            ("Linux", 32): cpuid_functions["cdecl.x86_32"],
            ("Linux", 64): cpuid_functions["Linux.x86_64"],
            ("Windows", 32): cpuid_functions["cdecl.x86_32"],
            ("Windows", 64): cpuid_functions["Windows.x86_64"],
        }
        cpuid_func = cpuid_functions_map.get((plat_sys, ptrsize))
        if cpuid_func is None:
            logger.error("Unsupported operating system")
            return None

        logger.debug("Using CPUID instruction for %d-bit %s", ptrsize, plat_sys)

        if plat_sys == "Linux":
            # Find functions in libc
            libc = ctypes.CDLL(ctypes.util.find_library("c"))
            libc.mmap.restype = ctypes.c_void_p
            libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

            # Allocate memory with a RW private anonymous mmap
            # PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
            mem = libc.mmap(0, len(cpuid_func), 3, 0x22, -1, 0)
            if int(mem) & 0xFFFFFFFF == 0xFFFFFFFF:
                libc.perror(b"mmap")
                return None

            # Copy the function
            ctypes.memmove(mem, cpuid_func, len(cpuid_func))

            # Change protection to RX
            if libc.mprotect(mem, len(cpuid_func), 5) == -1:
                libc.perror(b"mprotect")
                libc.munmap(mem, len(cpuid_func))
                return None

            # Transmute the memory to a suitable function
            memfun = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint32))(mem)

            # Use it and free it
            result = cls.decode_x86_cpuid_with_helper(memfun)
            libc.munmap(mem, len(cpuid_func))
            return result

        if plat_sys == "Windows":
            # https://github.com/flababah/cpuid.py/blob/master/cpuid.py says:
            # VirtualAlloc seems to fail under some weird
            # circumstances when ctypes.windll.kernel32 is
            # used under 64 bit Python. CDLL fixes this.
            if ptrsize == 64:
                k32 = ctypes.CDLL("kernel32.dll")
            else:
                k32 = ctypes.windll.kernel32  # type: ignore
            k32.VirtualAlloc.restype = ctypes.c_void_p
            int_p = ctypes.POINTER(ctypes.c_int)
            k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, int_p]
            k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]

            # Allocate RW memory of type MEM_COMMIT | MEM_RESERVE (=0x1000|0x2000)
            # PAGE_READWRITE = 4
            mem = k32.VirtualAlloc(0, len(cpuid_func), 0x3000, 4)
            if not mem:
                sys.stderr.write("VirtualAlloc: {}\n".format(ctypes.FormatError()))  # type: ignore
                return None

            # Copy the function
            ctypes.memmove(mem, cpuid_func, len(cpuid_func))

            # Change protection to PAGE_EXECUTE_READ = 0x20
            oldprot = ctypes.c_int()
            if not k32.VirtualProtect(mem, len(cpuid_func), 32, ctypes.byref(oldprot)):
                sys.stderr.write("VirtualProtect: {}\n".format(ctypes.FormatError()))  # type: ignore
                # MEM_RELEASE = 0x8000
                k32.VirtualFree(mem, len(cpuid_func), 0x8000)
                return None

            # Transmute the memory to a suitable function
            memfun = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint32))(mem)

            # Use it and free it
            result = cls.decode_x86_cpuid_with_helper(memfun)
            k32.VirtualFree(mem, len(cpuid_func), 0x8000)
            return result

        return None

    @staticmethod
    def decode_x86_cpuid_with_helper(
        cpuid_function,
    ):  # type: (Callable[[ctypes.Array[ctypes.c_uint32]], None]) -> X86CPUInfo
        def cpuid(code):  # type: (int) -> Tuple[int, int, int, int]
            regs = (ctypes.c_uint32 * 4)()
            regs[0] = code
            cpuid_function(regs)
            return (regs[0], regs[1], regs[2], regs[3])

        max_code, vendor0, vendor2, vendor1 = cpuid(0)
        vendor_id = struct.pack(b"<III", vendor0, vendor1, vendor2)
        cpuid_1 = cpuid(1)[0] if max_code >= 1 else 0

        max_extcode = cpuid(0x80000000)[0]
        if max_extcode >= 0x80000004:
            brand_string = b""
            for i in range(3):
                eax, ebx, ecx, edx = cpuid(0x80000002 + i)
                brand_string += struct.pack(b"<IIII", eax, ebx, ecx, edx)
            model_name = brand_string.decode("ascii").rstrip("\0").lstrip(" ")
        else:
            model_name = None
        return X86CPUInfo(vendor_id.decode("ascii"), model_name, cpuid_1)


CPU_MODELS = {
    "AuthenticAMD": load_x86_cpuid("amd_x86_cpuid.txt"),
    "GenuineIntel": load_x86_cpuid("intel_x86_cpuid.txt"),
}  # type: Dict[str, Dict[int, Dict[Tuple[int, int], CpuidInformation]]]


def main(argv=None):  # type: (Optional[Sequence[str]]) -> int
    """Program entry point"""
    parser = argparse.ArgumentParser(description="Find the CPU model")
    parser.add_argument("cpuinfo", nargs="*", type=str, help="analyze the given /proc/cpuinfo files")
    parser.add_argument("-d", "--debug", action="store_true", help="show debug messages")
    parser.add_argument("-l", "--list", action="store_true", help="list known CPUIDs")
    parser.add_argument("-m", "--list-microcodes", action="store_true", help="list known Microcodes")
    args = parser.parse_args(argv)
    logging.basicConfig(format="[%(levelname)-5s] %(message)s", level=logging.DEBUG if args.debug else logging.INFO)

    if args.list:
        for vendor, families in sorted(CPU_MODELS.items()):
            for family, models in sorted(families.items()):
                for model, stepping in sorted(models.keys()):
                    cpuid = X86CPUInfo.encode_cpuid(family, model, 15 if stepping == -1 else stepping)
                    cpuinfo_x86 = X86CPUInfo(vendor, None, cpuid)
                    desc_list = cpuinfo_x86.desc_cpuid()
                    desc = " ".join(desc_list[:2])
                    if stepping < 0:
                        desc = desc.replace(" stepping 15", "")
                    print(desc)
                    if len(desc_list) > 2:
                        print("\n".join(desc_list[2:]))

    if args.list_microcodes:
        for vendor, vendor_id, ucode_versions in (
            ("AMD", "AuthenticAMD", AMD_UCODE_VERSIONS),
            ("Intel", "GenuineIntel", INTEL_UCODE_VERSIONS),
        ):
            ucodes_for_cpuid = {}  # type: Dict[int, Dict[int, str]]
            for cpuid, microcode_version, update_date in ucode_versions:
                if cpuid not in ucodes_for_cpuid:
                    ucodes_for_cpuid[cpuid] = {}
                if microcode_version not in ucodes_for_cpuid[cpuid]:
                    ucodes_for_cpuid[cpuid][microcode_version] = update_date
                elif ucodes_for_cpuid[cpuid][microcode_version] < update_date:
                    # This can occur if a platform received an update with a
                    # different date
                    ucodes_for_cpuid[cpuid][microcode_version] = update_date
            for cpuid, ucodes in sorted(ucodes_for_cpuid.items()):
                cpuinfo_x86 = X86CPUInfo(vendor_id, None, cpuid)
                desc_list = cpuinfo_x86.desc_cpuid()
                print("{} {}".format(vendor, " ".join(desc_list[:2])))
                for microcode_version, update_date in sorted(ucodes.items()):
                    print("    Microcode version {:#x} {}".format(microcode_version, update_date))
                print("")

    if args.list or args.list_microcodes:
        return 0

    if args.cpuinfo:
        for ifile, filename in enumerate(args.cpuinfo):
            if ifile > 0:
                print("")
            cpuinfo = CPUInfo.decode_cpuinfo(filename)
            if cpuinfo is not None:
                print("{}:".format(filename))
                cpuinfo.describe()
    else:
        cpuinfo_proc = CPUInfo.decode_cpuinfo()
        cpuinfo_x86_cpuid = X86CPUInfo.decode_x86_cpuid()
        if cpuinfo_proc is not None:
            cpuinfo = cpuinfo_proc
            cpuinfo_k = cpuinfo.unique_key()
            if cpuinfo_x86_cpuid is not None and cpuinfo_x86_cpuid.unique_key() != cpuinfo_k:
                logger.warning("/proc/cpuinfo and cpuid disagree: %r vs %r", cpuinfo_proc, cpuinfo_x86_cpuid)
        elif cpuinfo_x86_cpuid is not None:
            cpuinfo = cpuinfo_x86_cpuid
        else:
            logger.error("Unable to find a source of CPU information")
            return 1
        cpuinfo.describe()

    return 0


if __name__ == "__main__":
    sys.exit(main())
