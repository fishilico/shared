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
"""Extract information from chipsec and sync the files

Chipsec (https://github.com/chipsec/chipsec) contains definitions of MSR and
processor platforms.

By default it downloads the main branch of Chipsec. Instead, a directory can
be provided to scan it.
"""
import argparse
import io
import re
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, FrozenSet, Optional, Tuple

from cpu_model import CPU_MODELS, X86CPUInfo
from x86_msr import MSRS

CHIPSEC_GIT_MAIN_ZIP_URL = "https://github.com/chipsec/chipsec/archive/refs/heads/main.zip"


# List of CPUID associations from Chipsec repository which are dubious/suspect
KNOWN_DUBIOUS_CPUID: FrozenSet[Tuple[int, str]] = frozenset(
    (
        (0x30690, "HSW"),  # Probably 0x4066x
        (0x30690, "HSX"),  # Probably 0x306cx
        (0x306E0, "SNB"),  # It is known as IVBX
        (0x306E2, "SNB"),  # It is known as IVBX
        (0x306E3, "SNB"),  # It is known as IVBX
        (0x306E4, "SNB"),  # It is known as IVBX
        (0x306F2, "IVB"),  # It is known as HSX-E/EP
        (0x40660, "HSX"),  # It is known as HSW
        (0x406E0, "SKX"),  # It is known as SKL
        (0x50655, "SKX"),  # It is known as CLX-SP
        (0x50656, "SKX"),  # It is known as CLX-SP
        (0x50657, "SKX"),  # It is known as CLX-SP
        (0x50658, "SKX"),
        (0x50659, "SKX"),
        (0x5065A, "SKX"),  # It is known as CPX-SP
        (0x5065B, "SKX"),  # It is known as CPX-SP
        (0x506E0, "SKX"),  # It is known as SKL
        (0x80670, "KBL"),
        (0x806C1, "TGLH"),
        (0x806C1, "TGLU"),
        (0x806C2, "TGLH"),
        (0x806C2, "TGLU"),
        (0x806D1, "TGLH"),
        (0x806D1, "TGLU"),
        (0x806EA, "WHL"),  # It is known as KBL-R-U/CFL-U43e
    )
)

KNOWN_NORMALIZED_MSR_NAMES: Dict[str, str] = {
    "PRMRR_PHYBASE": "PRMRR_BASE_0",
    "IA32_MSR_CORE_THREAD_COUNT": "CORE_THREAD_COUNT",
    "BIOS_SE_SVN_STATUS": "IA32_SGX_SVN_STATUS",
    "PRMRR_UNCORE_PHYBASE": "UNCORE_PRMRR_PHYS_BASE",
    "PRMRR_UNCORE_MASK": "UNCORE_PRMRR_PHYS_MASK",
    "APIC_BAR": "IA32_APIC_BASE",  # From AMD Renoir 0x1B
    "MTRRcap": "IA32_MTRRCAP",  # From AMD Renoir 0xFE
    "MCG_STAT": "IA32_MCG_STATUS",  # From AMD Renoir 0x17A
    "DBG_CTL_MSR": "IA32_DEBUGCTL",  # From AMD Renoir 0x1D9
    "BR_FROM": "LASTBRANCHFROMIP",  # From AMD Renoir 0x1DB
    "BR_TO": "LASTBRANCHTOIP",  # From AMD Renoir 0x1DC
    "LastExcpFromIp": "LASTINTFROMIP",  # From AMD Renoir 0x1DD
    "LastExcpToIp": "IA32_LER_TO_IP",  # From AMD Renoir 0x1DE
    "MtrrVarBase": "IA32_MTRR_PHYSBASE0",  # From AMD Renoir 0x200
    "MtrrVarMask": "IA32_MTRR_PHYSMASK0",  # From AMD Renoir 0x201
    "MtrrFix_64K": "IA32_MTRR_FIX64K_00000",  # From AMD Renoir 0x250
    "MtrrFix_16K_0": "IA32_MTRR_FIX16K_80000",  # From AMD Renoir 0x258
    "MtrrFix_16K_1": "IA32_MTRR_FIX16K_A0000",  # From AMD Renoir 0x259
    "MtrrFix_4K_0": "IA32_MTRR_FIX4K_C0000",  # From AMD Renoir 0x268
    "MtrrFix_4K_1": "IA32_MTRR_FIX4K_C8000",  # From AMD Renoir 0x269
    "MtrrFix_4K_2": "IA32_MTRR_FIX4K_D0000",  # From AMD Renoir 0x26A
    "MtrrFix_4K_3": "IA32_MTRR_FIX4K_D8000",  # From AMD Renoir 0x26B
    "MtrrFix_4K_4": "IA32_MTRR_FIX4K_E0000",  # From AMD Renoir 0x26C
    "MtrrFix_4K_5": "IA32_MTRR_FIX4K_E8000",  # From AMD Renoir 0x26D
    "MtrrFix_4K_6": "IA32_MTRR_FIX4K_F0000",  # From AMD Renoir 0x26E
    "MtrrFix_4K_7": "IA32_MTRR_FIX4K_F8000",  # From AMD Renoir 0x26F
    "MTRRdefType": "IA32_MTRR_DEF_TYPE",  # From AMD Renoir 0x2FF
    "STAR64": "IA32_LSTAR",  # From AMD Renoir 0xC0000082
    "STARCOMPAT": "IA32_CSTAR",  # From AMD Renoir 0xC0000083
    "SYSCALL_FLAG_MASK": "IA32_FMASK",  # From AMD Renoir 0xC0000084
    "MPerfReadOnly": "M_PERF_READ_ONLY",  # From AMD Renoir 0xC00000E7
    "APerfReadOnly": "A_PERF_READ_ONLY",  # From AMD Renoir 0xC00000E8
    "IRPerfCount": "IR_PERF_COUNT",  # From AMD Renoir 0xC00000E9
    "KernelGSbase": "IA32_KERNEL_GS_BASE",  # From AMD Renoir 0xC0000102
    "TscRateMsr": "TSC_RATIO",  # From AMD Renoir 0xC0000104
    "McaIntrCfg": "MCA_INTR_CFG",  # From AMD Renoir 0xC0000410
    "PERF_LEGACY_CTL": "PERFEVTSEL0",  # From AMD Renoir 0xC0010000
    "PERF_LEGACY_CTR": "PERFCTR0",  # From AMD Renoir 0xC0010004
    "SYS_CFG": "SYSCFG",  # From AMD Renoir 0xC0010010
    "IORR_BASE": "IORR_BASE_0",  # From AMD Renoir 0xC0010016
    "IORR_MASK": "IORR_MASK_0",  # From AMD Renoir 0xC0010017
    "TOM2": "TOP_MEM2",  # From AMD Renoir 0xC001001D
    "McExcepRedir": "MC_EXCEP_REDIR",  # From AMD Renoir 0xC0010022
    "ProcNameString": "PROCESSOR_NAME_STRING_0",  # From AMD Renoir 0xC0010030
    "SMI_ON_IO_TRAP": "IOTRAP_ADDR0",  # From AMD Renoir 0xC0010050
    "SMI_ON_IO_TRAP_CTL_STS": "IOTRAP_CTL",  # From AMD Renoir 0xC0010054
    "IntPend": "INT_PENDING_MSG",  # From AMD Renoir 0xC0010055
    "SmiTrigIoCycle": "SMI_TRIGGER_IO_CYCLE",  # From AMD Renoir 0xC0010056
    "MmioCfgBaseAddr": "MMIO_CFG_BASE_ADDR",  # From AMD Renoir 0xC0010058
    "PStateCurLim": "PSTATE_CURRENT_LIMIT",  # From AMD Renoir 0xC0010061
    "PStateCtl": "PSTATE_CONTROL",  # From AMD Renoir 0xC0010062
    "PStateStat": "PSTATE_STATUS",  # From AMD Renoir 0xC0010063
    "PStateDef": "PSTATE_DEF_0",  # From AMD Renoir 0xC0010064
    "CStateBaseAddr": "CSTATE_BASE_ADDR",  # From AMD Renoir 0xC0010073
    "CpuWdtCfg": "CPU_WATCHDOG_TIMER",  # From AMD Renoir 0xC0010074
    "SMM_BASE": "SMBASE",  # From AMD Renoir 0xC0010111
    "SMMAddr": "SMM_ADDR",  # From AMD Renoir 0xC0010112
    "SMMMask": "SMM_MASK",  # From AMD Renoir 0xC0010113
    "SvmLockKey": "SVM_KEY",  # From AMD Renoir 0xC0010118
    "LocalSmiStatus": "LOCAL_SMI_STATUS",  # From AMD Renoir 0xC001011A
    "AvicDoorbell": "SVM_AVIC_DOORBELL",  # From AMD Renoir 0xC001011B
    "GHCB": "SEV_ES_GHCB",  # From AMD Renoir 0xC0010130
    "SEV_Status": "SEV_STATUS",  # From AMD Renoir 0xC0010131
    "OSVW_ID_Length": "OSVW_ID_LENGTH",  # From AMD Renoir 0xC0010140
    "OSVW_Status": "OSVW_STATUS",  # From AMD Renoir 0xC0010141
    "PERF_CTL": "PERFEVTSEL0",  # From AMD Renoir 0xC0010200
    "PERF_CTR": "PERFCTR0",  # From AMD Renoir 0xC0010201
    "ChL3PmcCfg": "L2I_PERFEVTSEL0",  # From AMD Renoir 0xC0010230
    "ChL3Pmc": "L2I_PERFCTR0",  # From AMD Renoir 0xC0010231
    "DF_PERF_CTL": "NB_PERFEVTSEL0",  # From AMD Renoir 0xC0010240
    "DF_PERF_CTR": "NB_PERFCTR0",  # From AMD Renoir 0xC0010241
    "CPUID_7_Features": "CPUID_7_FEATURES",  # From AMD Renoir 0xC0011002
    "CPUID_Features": "CPUID_FEATURES",  # From AMD Renoir 0xC0011004
    "CPUID_ExtFeatures": "CPUID_EXT_FEATURES",  # From AMD Renoir 0xC0011005
    "TW_CFG": "CU_CFG",  # From AMD Renoir 0xC0011023
    "MCA_CTL_LS": "IA32_MC0_CTL",  # From AMD Renoir 0x400
    "MCA_STATUS_LS": "MCTR",  # From AMD Renoir 0x1
    "MCA_ADDR_LS": "MCAR",  # From AMD Renoir 0x0
    "MCA_MISC0_LS": "IA32_MC0_MISC",  # From AMD Renoir 0x403
    "MCA_CONFIG_LS": "MCA0_CONFIG",  # From AMD Renoir 0xC0002004
    "MCA_IPID_LS": "MCA0_IPID",  # From AMD Renoir 0xC0002005
    "MCA_SYND_LS": "MCA0_SYND",  # From AMD Renoir 0xC0002006
    "MCA_DESTAT_LS": "MCA0_DESTAT",  # From AMD Renoir 0xC0002008
    "MCA_DEADDR_LS": "MCA0_DEADDR",  # From AMD Renoir 0xC0002009
    "MCA_CTL_IF": "IA32_MC1_CTL",  # From AMD Renoir 0x404
    "MCA_STATUS_IF": "IA32_MC1_STATUS",  # From AMD Renoir 0x405
    "MCA_ADDR_IF": "IA32_MC1_ADDR",  # From AMD Renoir 0x406
    "MCA_MISC0_IF": "IA32_MC1_MISC",  # From AMD Renoir 0x407
    "MCA_CTL_L2": "IA32_MC2_CTL",  # From AMD Renoir 0x408
    "MCA_STATUS_L2": "IA32_MC2_STATUS",  # From AMD Renoir 0x409
    "MCA_ADDR_L2": "IA32_MC2_ADDR",  # From AMD Renoir 0x40A
    "MCA_MISC0_L2": "IA32_MC2_MISC",  # From AMD Renoir 0x40B
    "MCA_CTL_DE": "IA32_MC3_CTL",  # From AMD Renoir 0x40C
    "MCA_STATUS_DE": "IA32_MC3_STATUS",  # From AMD Renoir 0x40D
    "MCA_ADDR_DE": "IA32_MC3_ADDR",  # From AMD Renoir 0x40E
    "MCA_MISC0_DE": "IA32_MC3_MISC",  # From AMD Renoir 0x40F
    "MCA_CTL_EX": "IA32_MC5_CTL",  # From AMD Renoir 0x414
    "MCA_STATUS_EX": "IA32_MC5_STATUS",  # From AMD Renoir 0x415
    "MCA_ADDR_EX": "IA32_MC5_ADDR",  # From AMD Renoir 0x416
    "MCA_MISC0_EX": "IA32_MC5_MISC",  # From AMD Renoir 0x417
    "MCA_CTL_FP": "IA32_MC6_CTL",  # From AMD Renoir 0x418
    "MCA_STATUS_FP": "IA32_MC6_STATUS",  # From AMD Renoir 0x419
    "MCA_ADDR_FP": "IA32_MC6_ADDR",  # From AMD Renoir 0x41A
    "MCA_MISC0_FP": "IA32_MC6_MISC",  # From AMD Renoir 0x41B
    "MCA_CTL_L3": "IA32_MC7_CTL",  # From AMD Renoir 0x41C
    "MCA_STATUS_L3": "IA32_MC7_STATUS",  # From AMD Renoir 0x41D
    "MCA_ADDR_L3": "IA32_MC7_ADDR",  # From AMD Renoir 0x41E
    "MCA_MISC0_L3": "IA32_MC7_MISC",  # From AMD Renoir 0x41F
    "MCA_CTL_CS": "IA32_MC20_CTL",  # From AMD Renoir 0x450
    "MCA_STATUS_CS": "IA32_MC20_STATUS",  # From AMD Renoir 0x451
    "MCA_ADDR_CS": "IA32_MC20_ADDR",  # From AMD Renoir 0x452
    "MCA_MISC0_CS": "IA32_MC20_MISC",  # From AMD Renoir 0x453
    "MCA_CTL_PIE": "IA32_MC22_CTL",  # From AMD Renoir 0x458
    "MCA_STATUS_PIE": "IA32_MC22_STATUS",  # From AMD Renoir 0x459
    "MCA_ADDR_PIE": "IA32_MC22_ADDR",  # From AMD Renoir 0x45A
    "MCA_MISC0_PIE": "IA32_MC22_MISC",  # From AMD Renoir 0x45B
    "MCA_CTL_UMC": "IA32_MC15_CTL",  # From AMD Renoir 0x43C
    "MCA_STATUS_UMC": "IA32_MC15_STATUS",  # From AMD Renoir 0x43D
    "MCA_ADDR_UMC": "IA32_MC15_ADDR",  # From AMD Renoir 0x43E
    "MCA_MISC0_UMC": "IA32_MC15_MISC",  # From AMD Renoir 0x43F
}


def parse_chipsec_cfg(file_data: bytes) -> None:
    """Parse a XML file from chipsec/cfg/"""
    # We could parse an XML file... but the files are always well formed
    platform: Optional[str] = None
    for raw_line in file_data.splitlines():
        line = raw_line.decode()

        # Parse <configuration platform="...">
        if (
            "<configuration" in line
            and line != "<configuration>"
            and line != '<configuration platform="[PLATFORM_CODE]" req_pch="BOOLEAN">'
        ):
            if platform is not None:
                print(f"Warning: duplicate '<configuration' tag in {line!r}")
            if matches := re.match(r'^<configuration +platform="([0-9A-Za-z_]+)"', line):
                platform = matches.group(1)
            else:
                print(f"Warning: unable to parse platform from {line!r}")

        # Parse <info family="core" detection_value="...">
        # Ignore Intel Quark platform
        if platform != "QRK" and "<info" in line and "detection_value" in line:
            if matches := re.match(
                r'^ *<info family="(atom|core|quark|xeon)" detection_value="([0-9A-Fa-fx, -]+)"', line.replace("'", '"')
            ):
                family, detection_value = matches.groups()
                for values_str in detection_value.split(","):
                    values_str = values_str.strip().lower()
                    has_wildcard = False
                    if matches := re.match(r"^([0-9a-f]+)-([0-9a-f]+)$", values_str):
                        # Interval
                        values_start = int(matches.group(1), 16)
                        values_end = int(matches.group(2), 16)
                        if (values_start & ~0xF) != (values_end & ~0xF):
                            print(f"Warning: interval too large {values_str} in {line!r}")
                        values = list(range(values_start, values_end + 1))
                    elif matches := re.match(r"^([0-9a-f]+)$", values_str):
                        # Raw value
                        values = [int(matches.group(1), 16)]
                    elif matches := re.match(r"^([0-9a-f]+)x$", values_str):
                        # Unknown stepping
                        has_wildcard = True
                        values = [int(matches.group(1), 16) << 4]
                    else:
                        print(f"Warning: unknown detection_value format {values_str!r} in {line!r}")
                        values = []
                    for cpuid_value in values:
                        cpuinfo = X86CPUInfo("GenuineIntel", None, cpuid_value)
                        cpuid_desc = f"Intel {cpuinfo.x86_family}, {cpuinfo.x86_model:#x}, {cpuinfo.x86_stepping}"
                        cpu_models = CPU_MODELS.get(cpuinfo.vendor_id, {}).get(cpuinfo.x86_family)
                        if cpu_models is None:
                            print(f"Warning({cpuid_value:#x}): unknown Intel family {cpuinfo.x86_family}")
                            cpuid_data = None
                        elif has_wildcard:
                            cpuid_desc = f"Intel {cpuinfo.x86_family}, {cpuinfo.x86_model:#x}, any stepping"
                            assert cpuinfo.x86_stepping == 0  # This was the value set
                            cpuid_data = cpu_models.get((cpuinfo.x86_model, -1))
                        else:
                            cpuid_data = cpu_models.get((cpuinfo.x86_model, cpuinfo.x86_stepping))

                        if (cpuid_value, platform) in KNOWN_DUBIOUS_CPUID:
                            # Skip detection for known dubious assiociations
                            pass
                        elif cpuid_data is None:
                            print(f"Update({cpuid_value:#x}): {cpuid_desc} is {platform}")
                        else:
                            if cpuid_data[0] is None:
                                # No abbreviation
                                print(f"Update({cpuid_value:#x}): abbrev {platform} for {cpuid_desc} [{cpuid_data[1]}]")
                            elif platform not in cpuid_data[0]:
                                # Missing platform
                                print(
                                    f"Update({cpuid_value:#x}): missing {platform} in {cpuid_data[0]} for {cpuid_desc} [{cpuid_data[1]}]"  # noqa
                                )
            else:
                print(f"Warning: unable to parse info from {line!r}")

        if " msr=" in line.lower():
            if matches := re.match(r'^ *<register name="([0-9A-Za-z_]+)" +type="msr" msr="(0x[0-9A-F]+)"', line):
                msr_name, msr_index_hex = matches.groups()
                msr_index = int(msr_index_hex, 0)

                normalized_msr_name = msr_name
                if normalized_msr_name.startswith("MSR_"):
                    normalized_msr_name = normalized_msr_name[4:]
                if normalized_msr_name == "PRMRR_PHYBASE" and msr_index == 0x1F4:
                    normalized_msr_name = "PRMRR_PHYS_BASE"
                normalized_msr_name = KNOWN_NORMALIZED_MSR_NAMES.get(normalized_msr_name, normalized_msr_name)

                known_names = MSRS.msrs.get(msr_index)
                if not known_names:
                    if 0xC0002014 <= msr_index <= 0xC0002169 and msr_name.startswith(
                        ("MCA_CONFIG_", "MCA_IPID_", "MCA_SYND_", "MCA_DESTAT_", "MCA_DEADDR_", "MCA_MISC1_")
                    ):
                        # Ignore AMD Renoir MCA registers
                        pass
                    else:
                        print(f"Update(MSR 0x{msr_index:X}): new {msr_name}")
                elif (
                    normalized_msr_name not in known_names.values()
                    and ("IA32_" + normalized_msr_name) not in known_names.values()
                ):
                    # List known names
                    desc_names = " ".join(
                        f"{name}({prefix})" if prefix else name for prefix, name in sorted(known_names.items())
                    )
                    print(f"Update(MSR 0x{msr_index:X}): {msr_name} (known {desc_names})")
            else:
                print(f"Warning: unable to parse MSR definition from {line!r}")


def parse_chipsec_directory(directory: Path) -> None:
    """Parse files present in chipsec directory"""
    # When the Python module is installed, there is no "chipsec" directory
    for xml_pattern in ("chipsec/cfg/*/*.xml", "cfg/*/*.xml"):
        for config_file in sorted(directory.glob(xml_pattern)):
            print(f"Parsing {config_file.absolute()}")
            with config_file.open("rb") as stream:
                file_data = stream.read()
            parse_chipsec_cfg(file_data)


def parse_chipsec_from_github() -> None:
    """Download chipsec's main branch and analyze it"""
    print(f"Downloading {CHIPSEC_GIT_MAIN_ZIP_URL}")
    with urllib.request.urlopen(CHIPSEC_GIT_MAIN_ZIP_URL) as response:
        zip_data = response.read()
    with zipfile.ZipFile(io.BytesIO(zip_data), "r") as archive:
        for file_info in archive.infolist():
            if file_info.is_dir():
                continue
            if re.match(r"^.*chipsec/cfg/.*\.xml$", file_info.filename):
                print(f"Parsing {file_info.filename}")
                file_data = archive.read(file_info.filename)
                parse_chipsec_cfg(file_data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synchronize with chipsec definitions")
    parser.add_argument("chipsec", nargs="?", type=Path, help="directory where chipsec is cloned (optional)")
    args = parser.parse_args()

    if args.chipsec:
        parse_chipsec_directory(args.chipsec)
    else:
        parse_chipsec_from_github()
