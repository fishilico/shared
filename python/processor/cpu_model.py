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


logger = logging.getLogger(__name__)


def load_x86_cpuid(filename):
    """Load amd_x86_cpuid.txt and intel_x86_cpuid.txt"""
    models_by_family = {}
    current_family = None
    last_model_stepping = None
    with open(os.path.join(os.path.dirname(__file__), filename), "r") as fmicrocode:
        for line in fmicrocode:
            if "\t" in line:
                raise ValueError("Invalid line: tabulation is present in {}".format(repr(line)))

            line = line.rstrip()
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
                expected_cpuid_len = 6 if filename == "amd_x86_cpuid.txt" else 5
                if len(cpuid_str) != expected_cpuid_len:
                    raise ValueError("Invalid line: CPUID value not of the expected length {}".format(repr(line)))
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
                    raise ValueError("Invalid line: expected CPUID {:#x} != {:#x} in {}".format(
                        expected_cpuid, cpuid, repr(line)))

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
                    raise ValueError("Line out of order after ({:#x}, {}): {}".format(
                        last_model_stepping[0], last_model_stepping[1], repr(line)))
                last_model_stepping = (model, stepping)
                if last_model_stepping in models_by_family[current_family]:
                    raise ValueError("Invalid line: duplicate model, stepping in {}".format(repr(line)))
                models_by_family[current_family][last_model_stepping] = [acronym, main_desc]
                continue

            if last_model_stepping is not None and line.startswith("    "):
                name = line[4:]
                if name.startswith(" "):
                    raise ValueError("Invalid line: too many leading spaces in {}".format(repr(line)))
                if len(models_by_family[current_family][last_model_stepping]) == 2:
                    models_by_family[current_family][last_model_stepping].append([])
                models_by_family[current_family][last_model_stepping][2].append(name)
                continue

            raise ValueError("Invalid line: failed to match any known pattern {}".format(repr(line)))

    return models_by_family


def load_x86_microcode_versions(filename):
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
    0x41: ('ARM Limited', {  # 'A'
        0x000: 'Potenza',
        0x810: 'ARM810',
        0x920: 'ARM920',
        0x922: 'ARM922',
        0x926: 'ARM926',
        0x940: 'ARM940',
        0x946: 'ARM946',
        0x966: 'ARM966',
        0xa20: 'ARM1020',
        0xa22: 'ARM1022',
        0xa26: 'ARM1026',
        0xb02: 'ARM11 MPCore',
        0xb36: 'ARM1136',
        0xb56: 'ARM1156',
        0xb76: 'ARM1176',
        0xc05: 'Cortex-A5',
        0xc07: 'Cortex-A7',
        0xc08: 'Cortex-A8',
        0xc09: 'Cortex-A9',
        0xc0d: 'Cortex-A17',  # Originally A12
        0xc0f: 'Cortex-A15',
        0xc0e: 'Cortex-A17',
        0xc14: 'Cortex-R4',
        0xc15: 'Cortex-R5',
        0xc17: 'Cortex-R7',
        0xc18: 'Cortex-R8',
        0xc20: 'Cortex-M0',
        0xc21: 'Cortex-M1',
        0xc23: 'Cortex-M3',
        0xc24: 'Cortex-M4',
        0xc27: 'Cortex-M7',
        0xc60: 'Cortex-M0+',
        0xd00: 'Foundation',
        0xd01: 'Cortex-A32',
        0xd02: 'Cortex-A34',
        0xd03: 'Cortex-A53',
        0xd04: 'Cortex-A35',
        0xd05: 'Cortex-A55',
        0xd06: 'Cortex-A65',
        0xd07: 'Cortex-A57',
        0xd08: 'Cortex-A72',
        0xd09: 'Cortex-A73',
        0xd0a: 'Cortex-A75',
        0xd0b: 'Cortex-A76',
        0xd0c: 'Neoverse-N1',
        0xd0d: 'Cortex-A77',
        0xd0e: 'Cortex-A76AE',
        0xd0f: 'AEM-v8',
        0xd13: 'Cortex-R52',
        0xd15: 'Cortex-R82',
        0xd20: 'Cortex-M23',
        0xd21: 'Cortex-M33',
        0xd40: 'Neoverse-V1',
        0xd41: 'Cortex-A78',
        0xd42: 'Cortex-A78AE',
        0xd43: 'Cortex-A65AE',
        0xd44: 'Cortex-X1',
        0xd46: 'Cortex-A510',
        0xd47: 'Cortex-A710',
        0xd48: 'Cortex-X2',
        0xd49: 'Neoverse-N2',
        0xd4a: 'Neoverse-E1',
        0xd4b: 'Cortex-A78C',
        0xd4c: 'Cortex-X1C',
        0xd4d: 'Cortex-A715',
        0xd4e: 'Cortex-X3',
        0xd4f: 'Neoverse-V2',
    }),
    0x42: ('Broadcom', {  # 'B'
        0x00f: 'Brahma-B15',
        0x100: 'Brahma B53',
        0x516: 'Vulcan',  # "ThunderX2" in util-linux lscpu-arm
    }),
    0x43: ('Cavium', {  # 'C'
        0x0a0: 'ThunderX',
        0x0a1: 'ThunderX-88XX',
        0x0a2: 'ThunderX 81XX',
        0x0a3: 'ThunderX 83XX',
        0x0af: 'ThunderX2-99xx',
        0x0b0: 'OcteonTX2',
        0x0b1: 'OcteonTX2-98XX',
        0x0b2: 'OcteonTX2-96XX',
        0x0b3: 'OcteonTX2-95XX',
        0x0b4: 'OcteonTX2-95XXN',
        0x0b5: 'OcteonTX2-95XXMM',
        0x0b6: 'OcteonTX2-95XXO',
        0x0b8: 'ThunderX3-T110',
    }),
    0x44: ('DEC', {  # 'D'
        0xa10: 'SA110',
        0xa11: 'SA1100',
    }),
    0x46: ('Fujitsu', {  # 'F'
        0x001: 'A64FX',
    }),
    0x48: ('HiSilicon', {  # 'H'
        0xd01: 'TSV110, Kunpeng-920',
        0xd40: 'Cortex-A76',
    }),
    0x49: ('Infineon', {  # 'I'
    }),
    0x4d: ('Motorola/Freescale', {  # 'M'
    }),
    0x4e: ('NVidia', {  # 'N'
        0x000: 'Denver',
        0x003: 'Denver 2',
        0x004: 'Carmel',
    }),
    0x50: ('Applied Micro (APM)', {  # 'P'
        0x000: 'Potenza',  # "X-Gene" in util-linux lscpu-arm
    }),
    0x51: ('Qualcomm', {  # 'Q'
        0x00f: 'Scorpion',
        0x02d: 'Scorpion',
        0x04d: 'Krait',
        0x06f: 'Krait',
        0x200: 'Kryo',
        0x201: 'Kryo',
        0x205: 'Kryo',
        0x211: 'Kryo',
        0x800: 'Falkor v1, Kryo 2XX Gold',
        0x801: 'Kryo 2XX Silver',
        0x803: 'Kryo 3XX Silver',
        0x804: 'Kryo 4XX Gold',
        0x805: 'Kryo 4XX Silver',
        0xc00: 'Falkor',
        0xc01: 'Saphira',
    }),
    0x53: ('Samsung', {  # 'S'
        0x001: 'exynos-m1',
        0x002: 'exynos-m3',
        0x003: 'exynos-m4',
        0x004: 'exynos-m5',
    }),
    0x56: ('Marvell', {  # 'V'
        0x131: 'Feroceon-88FR131',
        0x581: 'PJ4/PJ4b',
        0x584: 'PJ4B-MP',
    }),
    0x61: ('Apple', {  # 'a'
        0x000: 'Swift',
        0x001: 'Cyclone',
        0x002: 'Typhoon',
        0x003: 'Typhoon/Capri',
        0x004: 'Twister',
        0x005: 'Twister/Elba/Malta',
        0x006: 'Hurricane',
        0x007: 'Hurricane/Myst',
        0x008: 'Monsoon',
        0x009: 'Mistral',
        0x00b: 'Vortex',
        0x00c: 'Tempest',
        0x00f: 'Tempest-M9',
        0x010: 'Vortex/Aruba',
        0x011: 'Tempest/Aruba',
        0x012: 'Lightning',
        0x013: 'Thunder',
        0x020: 'Icestorm-A14',
        0x021: 'Firestorm-A14',
        0x022: 'M1 Icestorm',
        0x023: 'M1 Firestorm',
        0x024: 'M1 Icestorm Pro',
        0x025: 'M1 Firestorm Pro',
        0x026: 'Thunder-M10',
        0x028: 'M1 Icestorm Max',
        0x029: 'M1 Firestorm Max',
        0x030: 'Blizzard-A15',
        0x031: 'Avalanche-A15',
        0x032: 'M2 Blizzard',
        0x033: 'M2 Avalanche',
        0x034: 'M2 Blizzard Pro',
        0x035: 'M2 Avalanche Pro',
        0x036: 'Sawtooth-A16',
        0x037: 'Everest-A16',
        0x038: 'M2 Blizzard Max',
        0x039: 'M2 Avalanche Max',
    }),
    0x66: ('Faraday', {  # 'f'
        0x526: 'FA526',
        0x626: 'FA626',
    }),
    0x69: ('Intel', {  # 'i'
        0x200: 'i80200',
        0x210: 'PXA250A',
        0x212: 'PXA210A',
        0x242: 'i80321-400',
        0x243: 'i80321-600',
        0x290: 'PXA250B/PXA26x',
        0x292: 'PXA210B',
        0x2c2: 'i80321-400-B0',
        0x2c3: 'i80321-600-B0',
        0x2d0: 'PXA250C/PXA255/PXA26x',
        0x2d2: 'PXA210C',
        0x411: 'PXA27x',
        0x41c: 'IPX425-533',
        0x41d: 'IPX425-400',
        0x41f: 'IPX425-266',
        0x682: 'PXA32x',
        0x683: 'PXA930/PXA935',
        0x688: 'PXA30x',
        0x689: 'PXA31x',
        0xb11: 'SA1110',
        0xc12: 'IPX1200',
    }),
    0x70: ('Phytium', {  # 'p'
        0x660: 'FTC660',
        0x661: 'FTC661',
        0x662: 'FTC662',
        0x663: 'FTC663',
    }),
    0xc0: ('Ampere', {
        0xac3: 'Ampere 1',
        0xac4: 'Ampere-1a',
    }),
}


class CPUInfo(object):
    """Information about a CPU"""
    def __init__(self, architecture):
        self.architecture = architecture

    @staticmethod
    def decode_cpuinfo(filename=None):
        """Build a CPUInfo object from /proc/cpuinfo content"""
        field_names = set((
            # x86
            'vendor_id',
            'cpu family',
            'model',
            'model name',
            'stepping',
            'microcode',

            # aarch64
            'CPU implementer',
            'CPU architecture',
            'CPU variant',
            'CPU part',
            'CPU revision',
        ))
        fields = {}
        if filename is None:
            filename = '/proc/cpuinfo'
            if not os.path.exists(filename):
                logger.debug("%s does not exist, skipping it", filename)
                return

        logger.debug("Reading %r", filename)
        with open(filename, 'r') as cpuinfo_file:
            for line in cpuinfo_file:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    if key in field_names:
                        # Decode the value if it is an int
                        if re.match(r'^[0-9]+$', value):
                            value = int(value)
                        elif re.match(r'^0x[0-9a-fA-F]+$', value):
                            value = int(value[2:], 16)
                        cur_value = fields.get(key)
                        if cur_value is None:
                            fields[key] = value
                        elif cur_value != value:
                            logger.error(
                                "CPU with different information: %s is %r and %r",
                                key, cur_value, value)

        vendor_id = fields.get('vendor_id')
        model_name = fields.get('model name')
        microcode_version = fields.get('microcode')
        if vendor_id is not None and model_name is not None:
            cpuid = None
            family = fields.get('cpu family')
            model = fields.get('model')
            stepping = fields.get('stepping')
            if family is not None and model is not None and stepping is not None:
                cpuid = X86CPUInfo.encode_cpuid(family, model, stepping)
            else:
                logger.error("CPUID components not found in %s", filename)
                return

            return X86CPUInfo(vendor_id, model_name, cpuid, microcode_version)

        implementer = fields.get('CPU implementer')
        architecture = fields.get('CPU architecture')
        if implementer is not None and architecture is not None:
            variant = fields.get('CPU variant')
            part = fields.get('CPU part')
            revision = fields.get('CPU revision')
            return Aarch64CPUInfo(implementer, architecture, variant, part, revision)

        logger.error(
            "Unable to find key fields in %s (vendor_id, CPU implementer, etc.)",
            filename)


class Aarch64CPUInfo(CPUInfo):
    """Information about an Aarch64 (ARM64) CPU from MIDR_EL1 register

    MIDR: Main ID Register
        ARM64: MRS <Xt>, MIDR_EL1
        ARM32: MRC p15, 0, <Rt>, c0, c0, 0

    It is also accessible from
    /sys/devices/system/cpu/cpu0/regs/identification/midr_el1
    """
    def __init__(self, implementer, architecture, variant, part, revision):
        super(Aarch64CPUInfo, self).__init__('aarch64')
        self.implementer = implementer
        self.architecture = architecture
        self.variant = variant
        self.part = part
        self.revision = revision

    def unique_key(self):
        """Get a unique key representing the CPU"""
        return self.architecture, self.implementer, self.architecture, self.variant, self.part, self.revision

    def __repr__(self):
        return '{}({}, {}, {}, {}, {})'.format(
            self.__class__.__name__,
            hex(self.implementer),
            hex(self.architecture),
            hex(self.variant),
            hex(self.part),
            hex(self.revision))

    def describe(self):
        impl_data = AARCH64_PARTS.get(self.implementer)
        if impl_data is not None:
            impl_name, impl_parts = impl_data
        else:
            impl_name = '?'
            impl_parts = {}

        print("- Implementer: {} ({:#x})".format(impl_name, self.implementer))
        print("- Part: {} ({:#x})".format(impl_parts.get(self.part, '?'), self.part))
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
    def __init__(self, vendor_id, model_name, cpuid, microcode_version=None):
        super(X86CPUInfo, self).__init__('x86')
        self.vendor_id = vendor_id
        self.model_name = model_name
        self.cpuid = cpuid
        self.microcode_version = microcode_version

    def unique_key(self):
        """Get a unique key representing the CPU"""
        return self.architecture, self.vendor_id, self.model_name, self.cpuid

    def __repr__(self):
        return '{}({}, {}, {}, {})'.format(
            self.__class__.__name__,
            repr(self.vendor_id),
            repr(self.model_name),
            hex(self.cpuid),
            hex(self.microcode_version) if self.microcode_version is not None else 'None')

    @staticmethod
    def encode_cpuid(family, model, stepping):
        """Encode the CPUID of x86 CPU"""
        assert 0 <= family <= 0xff + 0xf
        assert 0 <= model <= 0xff
        assert 0 <= stepping <= 0xf

        if family <= 0xf:
            base_family = family
            extended_family = 0
        else:
            base_family = 0xf
            extended_family = family - 0xf

        return (
            (extended_family << 20) |
            ((model & 0xf0) << 12) |
            (base_family << 8) |
            ((model & 0xf) << 4) |
            stepping)

    @property
    def x86_family(self):
        """Returns the family identifier, encoded in bits 8-11 and 20-27"""
        return ((self.cpuid >> 8) & 0xf) + ((self.cpuid >> 20) & 0xff)

    @property
    def x86_model(self):
        """Returns the model number, encoded in bits 4-7 and 16-19"""
        return ((self.cpuid >> 4) & 0xf) + ((self.cpuid >> 12) & 0xf0)

    @property
    def x86_stepping(self):
        return self.cpuid & 0xf

    def desc_cpuid(self):
        """Describe the cpuid signature in a list of strings"""
        lines = ["{0:#x} (family {1:d} model {2:d}={2:#x} stepping {3:d})".format(
            self.cpuid, self.x86_family, self.x86_model, self.x86_stepping)]
        cpu_models = CPU_MODELS.get(self.vendor_id, {}).get(self.x86_family)
        if cpu_models is not None:
            cpuid_data = cpu_models.get((self.x86_model, self.x86_stepping))
            if cpuid_data is None:
                cpuid_data = cpu_models.get((self.x86_model, -1))
            if cpuid_data is None:
                logger.warning("Unknown CPU family %d model %#x stepping %d",
                               self.x86_family, self.x86_model, self.x86_stepping)
            else:
                second_line = cpuid_data[1]
                if cpuid_data[0] is not None:
                    second_line = '"{}" {}'.format(cpuid_data[0], second_line)
                lines.append(second_line)
                if len(cpuid_data) > 2:
                    assert len(cpuid_data) == 3
                    for public_name in cpuid_data[2]:
                        lines.append("    {}".format(public_name))
        return lines

    def desc_microcode_version(self):
        """Describe the microcode version in a list of strings"""
        if self.microcode_version is None:
            return ['unknown']
        microcode_list = []
        version_date = None
        available_upgrade_ver = None
        available_upgrade_date = None
        if self.vendor_id == 'AuthenticAMD':
            ucode_versions = AMD_UCODE_VERSIONS
        elif self.vendor_id == 'GenuineIntel':
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
            lines.append("Available upgrade {:#x} from {}".format(
                available_upgrade_ver, available_upgrade_date))
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

    def describe(self):
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
    def decode_x86_cpuid(cls):
        """Run cpuid if on x86 to get the relevant CPUInfo"""
        plat_mach = platform.machine()
        plat_sys = platform.system()
        if plat_mach in ('AMD64', 'x86_64'):
            ptrsize = 64
        elif plat_mach in ('x86', 'i686'):
            ptrsize = 32
        else:
            logger.warning("Not using x86 cpuid instruction on %s", platform.machine())
            return

        if ptrsize != ctypes.sizeof(ctypes.c_voidp) * 8:
            logger.error(
                "platform.machine() %r is inconsistent with sizeof(void*) = %d",
                plat_mach, ctypes.sizeof(ctypes.c_voidp))
            return

        # Find a assembly function which performs:
        # void do_cpuid(uint32_t regs[4]) // regs are eax, ebx, ecx, edx
        # {
        #     __asm__ volatile ("cpuid"
        #         :"=a"(regs[0]), "=b"(regs[1]), "=c"(regs[2]), "=d"(regs[3])
        #         :"0"(regs[0]), "1"(regs[1]), "2"(regs[2]), "3"(regs[3]));
        # }
        cpuid_functions = {
            'cdecl.x86_32':
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
                b'VS\x8bt$\x0c\x8b\x06\x8b^\x04\x8bN\x08\x8bV\x0c' +
                b'\x0f\xa2\x89\x06\x89^\x04\x89N\x08\x89V\x0c[^\xc3',
            'Linux.x86_64':
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
                b'S\x8b\x07\x8b_\x04\x8bO\x08\x8bW\x0c' +
                b'\x0f\xa2\x89_\x04\x89\x07\x89O\x08\x89W\x0c[\xc3',
            'Windows.x86_64':
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
                b'S\x8b\x01\x8bY\x04I\x89\xc8\x8bI\x08A\x8bP\x0c' +
                b'\x0f\xa2A\x89\x00A\x89X\x04A\x89H\x08A\x89P\x0c[\xc3',
        }
        cpuid_functions_map = {
            ('Linux', 32): cpuid_functions['cdecl.x86_32'],
            ('Linux', 64): cpuid_functions['Linux.x86_64'],
            ('Windows', 32): cpuid_functions['cdecl.x86_32'],
            ('Windows', 64): cpuid_functions['Windows.x86_64'],
        }
        cpuid_func = cpuid_functions_map.get((plat_sys, ptrsize))
        if cpuid_func is None:
            logger.error("Unsupported operating system")
            return

        logger.debug("Using CPUID instruction for %d-bit %s", ptrsize, plat_sys)

        if plat_sys == 'Linux':
            # Find functions in libc
            libc = ctypes.CDLL(ctypes.util.find_library('c'))
            libc.mmap.restype = ctypes.c_void_p
            libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

            # Allocate memory with a RW private anonymous mmap
            # PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
            mem = libc.mmap(0, len(cpuid_func), 3, 0x22, -1, 0)
            if int(mem) & 0xffffffff == 0xffffffff:
                libc.perror(b"mmap")
                return

            # Copy the function
            ctypes.memmove(mem, cpuid_func, len(cpuid_func))

            # Change protection to RX
            if libc.mprotect(mem, len(cpuid_func), 5) == -1:
                libc.perror(b"mprotect")
                libc.munmap(mem, len(cpuid_func))
                return

            # Transmute the memory to a suitable function
            memfun = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint32))(mem)

            # Use it and free it
            result = cls.decode_x86_cpuid_with_helper(memfun)
            libc.munmap(mem, len(cpuid_func))
            return result

        if plat_sys == 'Windows':
            # https://github.com/flababah/cpuid.py/blob/master/cpuid.py says:
            # VirtualAlloc seems to fail under some weird
            # circumstances when ctypes.windll.kernel32 is
            # used under 64 bit Python. CDLL fixes this.
            if ptrsize == 64:
                k32 = ctypes.CDLL("kernel32.dll")
            else:
                k32 = ctypes.windll.kernel32
            k32.VirtualAlloc.restype = ctypes.c_void_p
            int_p = ctypes.POINTER(ctypes.c_int)
            k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                           ctypes.c_int, int_p]
            k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                        ctypes.c_int]

            # Allocate RW memory of type MEM_COMMIT | MEM_RESERVE (=0x1000|0x2000)
            # PAGE_READWRITE = 4
            mem = k32.VirtualAlloc(0, len(cpuid_func), 0x3000, 4)
            if not mem:
                sys.stderr.write("VirtualAlloc: {}\n".format(ctypes.FormatError()))
                return

            # Copy the function
            ctypes.memmove(mem, cpuid_func, len(cpuid_func))

            # Change protection to PAGE_EXECUTE_READ = 0x20
            oldprot = ctypes.c_int()
            if not k32.VirtualProtect(mem, len(cpuid_func), 32, ctypes.byref(oldprot)):
                sys.stderr.write("VirtualProtect: {}\n".format(ctypes.FormatError()))
                # MEM_RELEASE = 0x8000
                k32.VirtualFree(mem, len(cpuid_func), 0x8000)
                return

            # Transmute the memory to a suitable function
            memfun = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint32))(mem)

            # Use it and free it
            result = cls.decode_x86_cpuid_with_helper(memfun)
            k32.VirtualFree(mem, len(cpuid_func), 0x8000)
            return result

    @classmethod
    def decode_x86_cpuid_with_helper(cls, cpuid_function):
        def cpuid(code):
            regs = (ctypes.c_uint32 * 4)()
            regs[0] = code
            cpuid_function(regs)
            return regs
        max_code, vendor0, vendor2, vendor1 = cpuid(0)
        vendor_id = struct.pack(b'<III', vendor0, vendor1, vendor2)
        cpuid_1 = cpuid(1)[0] if max_code >= 1 else 0

        max_extcode = cpuid(0x80000000)[0]
        if max_extcode >= 0x80000004:
            brand_string = b''
            for i in range(3):
                eax, ebx, ecx, edx = cpuid(0x80000002 + i)
                brand_string += struct.pack(b'<IIII', eax, ebx, ecx, edx)
            model_name = brand_string.decode('ascii').rstrip('\0').lstrip(' ')
        else:
            model_name = None
        return X86CPUInfo(vendor_id.decode('ascii'), model_name, cpuid_1)


CPU_MODELS = {
    "AuthenticAMD": load_x86_cpuid("amd_x86_cpuid.txt"),
    "GenuineIntel": load_x86_cpuid("intel_x86_cpuid.txt"),
}


def main(argv=None):
    """Program entry point"""
    parser = argparse.ArgumentParser(description="Find the CPU model")
    parser.add_argument('cpuinfo', nargs='*', type=str,
                        help="analyze the given /proc/cpuinfo files")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-l', '--list', action='store_true',
                        help="list known CPUIDs")
    parser.add_argument('-m', '--list-microcodes', action='store_true',
                        help="list known Microcodes")
    args = parser.parse_args(argv)
    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    if args.list:
        for vendor, families in sorted(CPU_MODELS.items()):
            for family, models in sorted(families.items()):
                for model, stepping in sorted(models.keys()):
                    cpuid = X86CPUInfo.encode_cpuid(family, model, 15 if stepping == -1 else stepping)
                    cpuinfo = X86CPUInfo(vendor, None, cpuid)
                    desc_list = cpuinfo.desc_cpuid()
                    desc = ' '.join(desc_list[:2])
                    if stepping < 0:
                        desc = desc.replace(' stepping 15', '')
                    print(desc)
                    if len(desc_list) > 2:
                        print('\n'.join(desc_list[2:]))

    if args.list_microcodes:
        for vendor, vendor_id, ucode_versions in (
            ("AMD", "AuthenticAMD", AMD_UCODE_VERSIONS),
            ("Intel", "GenuineIntel", INTEL_UCODE_VERSIONS),
        ):
            ucodes_for_cpuid = {}
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
                cpuinfo = X86CPUInfo(vendor_id, None, cpuid)
                desc_list = cpuinfo.desc_cpuid()
                print('{} {}'.format(vendor, ' '.join(desc_list[:2])))
                for microcode_version, update_date in sorted(ucodes.items()):
                    print('    Microcode version {:#x} {}'.format(
                        microcode_version, update_date))
                print('')

    if args.list or args.list_microcodes:
        return 0

    if args.cpuinfo:
        for ifile, filename in enumerate(args.cpuinfo):
            if ifile > 0:
                print('')
            cpuinfo = CPUInfo.decode_cpuinfo(filename)
            if cpuinfo is not None:
                print("{}:".format(filename))
                cpuinfo.describe()
    else:
        cpuinfo_proc = CPUInfo.decode_cpuinfo()
        cpuinfo_x86 = X86CPUInfo.decode_x86_cpuid()
        if cpuinfo_proc is not None:
            cpuinfo = cpuinfo_proc
            cpuinfo_k = cpuinfo.unique_key()
            if cpuinfo_x86 is not None and cpuinfo_x86.unique_key() != cpuinfo_k:
                logger.warning("/proc/cpuinfo and cpuid disagree: %r vs %r",
                               cpuinfo_proc, cpuinfo_x86)
        elif cpuinfo_x86 is not None:
            cpuinfo = cpuinfo_x86
        else:
            logger.error("Unable to find a source of CPU information")
            return 1
        cpuinfo.describe()

    return 0


if __name__ == '__main__':
    sys.exit(main())
