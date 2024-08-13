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
"""Extract information from Linux source code"""
import argparse
import re
import sys
import urllib.request
from pathlib import Path
from typing import FrozenSet, List, Mapping, Optional, Tuple

from cpu_model import CPU_MODELS, CpuidInformation
from x86_msr import MSRS

LINUX_GIT_PLAIN_URL = "https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain"

# Known associations between filename and model name
KNOWN_FILENAME_MODEL: FrozenSet[Tuple[str, str]] = frozenset(
    (
        ("alderlake", "Alder Lake P"),
        ("alderlake", "Alder Lake"),
        ("alderlake", "Raptor Lake P"),
        ("alderlake", "Raptor Lake S, Bartlett Lake S"),
        ("alderlaken", "Alder Lake N, Twin Lake"),
        ("bonnell", "Atom Bonnell Mid"),
        ("bonnell", "Atom Bonnell"),
        ("bonnell", "Atom Bonnel, Atom Saltwell Mid"),
        ("bonnell", "Atom Bonnel, Atom Saltwell Tablet"),
        ("bonnell", "Atom Bonnel, Atom Saltwell"),
        ("broadwell", "Broadwell"),
        ("broadwell", "Broadwell-G"),
        ("broadwellde", "Broadwell Xeon DE"),
        ("broadwellx", "Broadwell Xeon"),
        ("cascadelakex", "Cascade Lake Server"),
        ("emeraldrapids", "Emerald Rapids Xeon"),
        ("elkhartlake", "Elkhart Lake"),
        ("elkhartlake", "Jasper Lake"),
        ("goldmont", "Atom Goldmont D"),
        ("goldmont", "Atom Goldmont"),
        ("goldmontplus", "Atom Goldmont Plus"),
        ("grandridge", "Grand Ridge"),
        ("graniterapids", "Granite Rapids D"),
        ("graniterapids", "Granite Rapids Xeon"),
        ("haswell", "Haswell"),
        ("haswellx", "Haswell X"),
        ("icelake", "Ice Lake Desktop"),
        ("icelake", "Ice Lake Mobile"),
        ("icelake", "Rocket Lake"),
        ("icelakex", "Ice Lake Xeon D"),
        ("icelakex", "Ice Lake"),
        ("ivybridge", "Ivy Bridge"),
        ("ivytown", "Ivy Bridge Xeon"),
        ("jaketown", "Sandy Bridge Xeon"),
        ("knightslanding", "Xeon Phi Knights Landing"),
        ("knightslanding", "Xeon Phi Knights Mill"),
        ("lunarlake", "Lunar Lake M"),
        ("meteorlake", "Meteor Lake M and P"),
        ("meteorlake", "Meteor Lake S"),
        ("nehalemep", "Nehalem EP"),
        ("nehalemep", "Nehalem"),
        ("nehalemex", "Nehalem-EX"),
        ("rocketlake", "Rocket Lake"),
        ("sandybridge", "Sandy Bridge"),
        ("sapphirerapids", "Sapphire Rapids Xeon"),
        ("sierraforest", "Sierra Forest Xeon"),
        ("silvermont", "Atom Silvermont, Atom Airmont Mid"),
        ("silvermont", "Atom Silvermont, Atom Airmont"),
        ("silvermont", "Atom Merrifield , Atom Silvermont Mid"),
        ("silvermont", "Atom Silvermont D"),
        ("silvermont", "Atom Silvermont"),
        ("skylake", "Comet Lake"),
        ("skylake", "Kaby Lake"),
        ("skylake", "Skylake"),
        ("skylake", "Skylake-L"),
        ("skylakex", "Skylake Server"),
        ("snowridgex", "Snow Ridge, Atom Tremont X"),
        ("tigerlake", "Tiger Lake"),
        ("westmereep-dp", "Westmere DP"),
        ("westmereep-sp", "Westmere"),
        ("westmereex", "Westmere-EX"),
    )
)

emitted_warning = False


def parse_perf_events_x86_mapfile(content: str, verbose: bool = False) -> None:
    """Parse tools/perf/pmu-events/arch/x86/mapfile.csv"""
    global emitted_warning
    for line in content.splitlines():
        if line == "Family-model,Version,Filename,EventType":
            # Skip the header from Linux
            continue
        if line.startswith("AuthenticAMD-"):
            # Skip AMD specifications
            continue
        # Match "GenuineIntel-6-55-[56789ABCDEF],v1.17,cascadelakex,core"
        # and "GenuineIntel-6-(97|9A|B7|BA|BF),v1.16,alderlake,core"
        matches = re.match(r"^(GenuineIntel)-(6)-([0-9A-F()\[\]|-]+),v[0-9.]+,([a-z-]+),core$", line)
        if not matches:
            raise ValueError(f"Unexpected line in mapfile.csv: {line!r}")
        vendor, fam_str, model_str, filename = matches.groups()
        family = int(fam_str)

        cpu_models = CPU_MODELS.get(vendor, {}).get(family)
        if cpu_models is None:
            print(f"Warning(mapfile, {line!r}): unknown {vendor} family {family}")
            emitted_warning = True
            continue
        cpuid_data: List[Tuple[int, Optional[CpuidInformation]]]
        # The stepping is specific with model 55
        if model_str.startswith("55-"):
            if model_str == "55-[01234]":
                cpuid_data = [(0x55, cpu_models.get((0x55, 0)))]
            elif model_str == "55-[56789ABCDEF]":
                cpuid_data = [(0x55, cpu_models.get((0x55, 5)))]
            else:
                print(f"Warning(mapfile, {line!r}): stepping for model 0x55")
                emitted_warning = True
                continue
        else:
            # Expand the model
            if re.match(r"^[0-9A-F][0-9A-F]$", model_str):
                models = [int(model_str, 16)]
            elif re.match(r"^\(([0-9A-F][0-9A-F]\|)+[0-9A-F][0-9A-F]\)$", model_str):
                models = [int(m, 16) for m in model_str[1:-1].split("|")]
            elif re.match(r"^[0-9A-F]\[[0-9A-F]+\]$", model_str):
                high_hexdigit = int(model_str[0], 16) << 4
                models = [high_hexdigit | int(low, 16) for low in model_str[2:-1]]
            else:
                print(f"Warning(mapfile, {line!r}): Unsupported {model_str}")
                emitted_warning = True
                continue
            # print(f"{model_str!r} -> {models!r}")
            cpuid_data = [(m, cpu_models.get((m, -1))) for m in models]

        for model, model_data in cpuid_data:
            if model_data is None:
                print(f"Warning(mapfile, {line!r}): Unknown model {model:#04x}")
                emitted_warning = True
                continue
            acronym = model_data.acronym or "?"
            name = model_data.main_desc
            if verbose:
                print(f"{model:#04x}: {filename:15} {acronym:7} {name}")
            # Strip parenthesis from the name
            while m := re.match(r"^(.* )\([^)]*\)(.*)$", name):
                name = (m.group(1) + m.group(2)).strip()
            if (filename, name) not in KNOWN_FILENAME_MODEL:
                print(f"Warning(mapfile, {line!r}): missing association in known list {(filename, name)!r}")
                emitted_warning = True


# Name of bit fields in the value of a MSR in
# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/msr-index.h
KNOWN_MSR_BIT_FIELD_NAMES: FrozenSet[str] = frozenset(
    (
        "AMD64_IBSFETCH_REG_COUNT",
        "AMD64_IBSOP_REG_COUNT",
        "AMD64_IBS_REG_COUNT_MAX",
        "IA32_BNDCFGS_RSVD",
        "IA32_POWER_CTL_BIT_EE",
        "IA32_VMX_MISC_PREEMPTION_TIMER_SCALE",
    )
)

LINUX_MSR_MAPPING: Mapping[str, str] = {
    "AMD64_BU_CFG2": "AMD64_CU_CFG2",
    "AMD64_CPUID_FN_1": "AMD64_CPUID_FEATURES",
    "AMD64_IBSBRTARGET": "AMD64_BP_IBSTGT_RIP",
    "AMD64_IBSCTL": "AMD64_IBS_CTL",
    "AMD64_IBSDCLINAD": "AMD64_IBS_DC_LINADDR",
    "AMD64_IBSDCPHYSAD": "AMD64_IBS_DC_PHYSADDR",
    "AMD64_IBSFETCHCTL": "AMD64_IBS_FETCH_CTL",
    "AMD64_IBSFETCHLINAD": "AMD64_IBS_FETCH_LINADDR",
    "AMD64_IBSFETCHPHYSAD": "AMD64_IBS_FETCH_PHYSADDR",
    "AMD64_IBSOPCTL": "AMD64_IBS_OP_CTL",
    "AMD64_IBSOPDATA": "AMD64_IBS_OP_DATA",
    "AMD64_IBSOPDATA2": "AMD64_IBS_OP_DATA2",
    "AMD64_IBSOPDATA3": "AMD64_IBS_OP_DATA3",
    "AMD64_IBSOPDATA4": "AMD64_IBS_OP_DATA4",
    "AMD64_IBSOPRIP": "AMD64_IBS_OP_RIP",
    "AMD64_ICIBSEXTDCTL": "AMD64_IC_IBS_EXTD_CTL",
    "AMD64_INT_PENDING_MSG": "AMD64_INT_PEND",
    "AMD64_LBR_SELECT": "AMD64_LAST_BRANCH_STACK_SELECT",
    "AMD64_MC0_MASK": "AMD64_MC0_CTL_MASK",
    "AMD64_SEV": "AMD64_SEV_STATUS",
    "AMD64_VM_PAGE_FLUSH": "AMD64_VMPAGE_FLUSH",
    "AMD_CORE_ENERGY_STATUS": "AMD64_CORE_ENERGY_STAT",
    "AMD_CPPC_CAP1": "AMD64_CAP1",
    "AMD_CPPC_CAP2": "AMD64_CPPC_CAP2",
    "AMD_CPPC_ENABLE": "AMD64_CPPC_ENABLE",
    "AMD_CPPC_REQ": "AMD64_CPPC_REQ",
    "AMD_CPPC_STATUS": "AMD64_CPPC_STATUS",
    "AMD_DBG_EXTN_CFG": "AMD64_DEBUG_EXTN_CTL",
    "AMD_PERF_CTL": "AMD64_PSTATE_CONTROL",
    "AMD_PERF_STATUS": "AMD64_PSTATE_STATUS",
    "AMD_PKG_ENERGY_STATUS": "AMD64_PKG_ENERGY_STAT",
    "AMD_PPIN": "AMD64_PPIN",
    "AMD_PPIN_CTL": "AMD64_PPIN_CTL",
    "AMD_PSTATE_DEF_BASE": "AMD64_PSTATE_DEF_0",
    "AMD_RAPL_POWER_UNIT": "AMD64_RAPL_PWR_UNIT",
    "AMD_SAMP_BR_FROM": "AMD64_LASTBRANCH_STACK_FROM_IP_0",
    "ARCH_LBR_FROM_0": "IA32_LBR_0_FROM_IP",
    "ARCH_LBR_INFO_0": "IA32_LBR_0_INFO",
    "ARCH_LBR_TO_0": "IA32_LBR_0_TO_IP",
    "CONFIG_TDP_LEVEL_1": "CONFIG_TDP_LEVEL1",
    "CONFIG_TDP_LEVEL_2": "CONFIG_TDP_LEVEL2",
    "CORE_C1_RES": "CORE_C1_RESIDENCY",
    "F10H_DECFG": "AMD64_DE_CFG",
    "F15H_CU_MAX_PWR_ACCUMULATOR": "AMD64_CU_MAX_PWR_ACCUMULATOR",
    "F15H_CU_PWR_ACCUMULATOR": "AMD64_CU_PWR_ACCUMULATOR",
    "F15H_EX_CFG": "AMD64_EX_CFG",
    "F15H_IC_CFG": "AMD64_IC_CFG",
    "F15H_NB_PERF_CTL": "AMD64_NB_PERFEVTSEL0",
    "F15H_NB_PERF_CTR": "AMD64_NB_PERFCTR0",
    "F15H_PERF_CTL": "AMD64_PERFEVTSEL0",
    "F15H_PERF_CTR": "AMD64_PERFCTR0",
    "F15H_PTSC": "AMD64_PTSC",
    "F16H_DR0_ADDR_MASK": "AMD64_DR0_ADDR_MASK",
    "F16H_DR1_ADDR_MASK": "AMD64_DR1_ADDR_MASK",
    "F16H_DR2_ADDR_MASK": "AMD64_DR2_ADDR_MASK",
    "F16H_DR3_ADDR_MASK": "AMD64_DR3_ADDR_MASK",
    "F16H_L2I_PERF_CTL": "AMD64_L2I_PERFEVTSEL0",
    "F16H_L2I_PERF_CTR": "AMD64_L2I_PERFCTR0",
    "F17H_IRPERF": "AMD64_IR_PERF_COUNT",
    "FAM10H_MMIO_CONF_BASE": "AMD64_MMIO_CFG_BASE_ADDR",
    "FAM10H_NODE_ID": "AMD64_NODE_ID",
    "GFX_PERF_LIMIT_REASONS": "GRAPHICS_PERF_LIMIT_REASONS",
    "IA32_APICBASE": "IA32_APIC_BASE",
    "IA32_BBL_CR_CTL": "BBL_CR_CTL",
    "IA32_BBL_CR_CTL3": "BBL_CR_CTL3",
    "IA32_CORE_CAPS": "IA32_CORE_CAPABILITIES",
    "IA32_CR_PAT": "IA32_PAT",
    "IA32_DEBUGCTLMSR": "IA32_DEBUGCTL",
    "IA32_EBL_CR_POWERON": "EBL_CR_POWERON",
    "IA32_EVT_CFG_BASE": "AMD64_EVT_CFG_BASE",
    "IA32_FEAT_CTL": "IA32_FEATURE_CONTROL",
    "IA32_INT_SSP_TAB": "IA32_INTERRUPT_SSP_TABLE_ADDR",
    "IA32_L2_CBM_BASE": "IA32_L2_MASK_0",
    "IA32_L3_CBM_BASE": "IA32_L3_MASK_0",
    "IA32_LASTBRANCHFROMIP": "LASTBRANCHFROMIP",
    "IA32_LASTBRANCHTOIP": "LASTBRANCHTOIP",
    "IA32_LASTINTFROMIP": "LASTINTFROMIP",
    "IA32_LASTINTTOIP": "LASTINTTOIP",
    "IA32_MBA_BW_BASE": "AMD64_MBA_BW_0",
    "IA32_MBA_THRTL_BASE": "MBA_THRTL_0",
    "IA32_MCG_RESERVED": "MCG_MISC",
    "IA32_PERFCTR0": "IA32_PMC0",
    "IA32_PERFCTR1": "IA32_PMC1",
    "IA32_PMC0": "IA32_A_PMC0",
    "IA32_POWER_CTL": "POWER_CTL",
    "IA32_RTIT_OUTPUT_MASK": "IA32_RTIT_OUTPUT_MASK_PTRS",
    "IA32_SMBA_BW_BASE": "AMD64_SMBA_BW_BASE",
    "IA32_TEMPERATURE_TARGET": "TEMPERATURE_TARGET",
    "IA32_THERM_CONTROL": "IA32_CLOCK_MODULATION",  # WTF?
    "IA32_TSC": "IA32_TIME_STAMP_COUNTER",
    "IA32_UCODE_REV": "IA32_BIOS_SIGN_ID",
    "IA32_UCODE_WRITE": "IA32_BIOS_UPDT_TRIG",
    "INTEGRITY_CAPS": "INTEGRITY_CAPABILITIES",
    "K7_FID_VID_CTL": "K7_FIDVID_CTL",
    "K7_FID_VID_STATUS": "K7_FIDVID_STATUS",
    "K8_TOP_MEM1": "K8_TOP_MEM",
    "K8_TSEG_ADDR": "K8_SMM_ADDR",
    "K8_TSEG_MASK": "K8_SMM_MASK",
    "LBR_TOS": "LASTBRANCH_TOS",
    "MISC_FEATURES_ENABLES": "MISC_FEATURE_ENABLES",
    "MODULE_C6_RES_MS": "MC6_RESIDENCY_COUNTER",
    "MTRRcap": "MTRRCAP",
    "MTRRdefType": "IA32_MTRR_DEF_TYPE",
    "P4_BPU_PERFCTR0": "P4_BPU_COUNTER0",
    "P4_BPU_PERFCTR1": "P4_BPU_COUNTER1",
    "P4_BPU_PERFCTR2": "P4_BPU_COUNTER2",
    "P4_BPU_PERFCTR3": "P4_BPU_COUNTER3",
    "P4_FLAME_PERFCTR0": "P4_FLAME_COUNTER0",
    "P4_FLAME_PERFCTR1": "P4_FLAME_COUNTER1",
    "P4_FLAME_PERFCTR2": "P4_FLAME_COUNTER2",
    "P4_FLAME_PERFCTR3": "P4_FLAME_COUNTER3",
    "P4_IQ_PERFCTR0": "P4_IQ_COUNTER0",
    "P4_IQ_PERFCTR1": "P4_IQ_COUNTER1",
    "P4_IQ_PERFCTR2": "P4_IQ_COUNTER2",
    "P4_IQ_PERFCTR3": "P4_IQ_COUNTER3",
    "P4_IQ_PERFCTR4": "P4_IQ_COUNTER4",
    "P4_IQ_PERFCTR5": "P4_IQ_COUNTER5",
    "P4_MS_PERFCTR0": "P4_MS_COUNTER0",
    "P4_MS_PERFCTR1": "P4_MS_COUNTER1",
    "P4_MS_PERFCTR2": "P4_MS_COUNTER2",
    "P4_MS_PERFCTR3": "P4_MS_COUNTER3",
    "P6_EVNTSEL0": "IA32_PERFEVTSEL0",
    "P6_EVNTSEL1": "IA32_PERFEVTSEL1",
    "P6_PERFCTR0": "IA32_PMC0",
    "P6_PERFCTR1": "IA32_PMC1",
    "PEBS_LD_LAT_THRESHOLD": "PEBS_LD_LAT",
    "PERF_LIMIT_REASONS": "CORE_PERF_LIMIT_REASONS",
    "PKG_ANY_CORE_C0_RES": "ANY_CORE_C0",
    "PKG_ANY_GFXE_C0_RES": "ANY_GFXE_C0",
    "PKG_BOTH_CORE_GFXE_C0_RES": "CORE_GFXE_OVERLAP_C0",
    "PKG_WEIGHTED_CORE_C0_RES": "WEIGHTED_CORE_C0",
    "PLATFORM_ENERGY_STATUS": "PLATFORM_ENERGY_COUNTER",
    "RMID_SNC_CONFIG": "RMID_SNC_DISABLE",
    "SYSCALL_MASK": "IA32_FMASK",
    "TEST_CTRL": "TEST_CTL",
    "VM_IGNNE": "IGNNE",
    "ZEN2_SPECTRAL_CHICKEN": "ZEN2_DE_CFG2",
}


def parse_msr_define(content: str, verbose: bool = False) -> None:
    """Load MSR from arch/x86/include/asm/msr-index.h"""
    global emitted_warning
    for line in content.splitlines():
        if matches := re.match(r"^#define\s+MSR_(\S*)\s+([0-9a-fA-Fx]+)(\s.*)?$", line):
            name = matches.group(1)
            value = int(matches.group(2), 0)
            # Skip definition of bit fields in the value of a MSR
            if name in KNOWN_MSR_BIT_FIELD_NAMES:
                continue
            if name.endswith("_BIT") and 0 <= value <= 63:
                continue

            # Skip "step" value
            if name == "IA32_PMC_V6_STEP" and value == 4:
                continue

            name = LINUX_MSR_MAPPING.get(name, name)

            # Map the macro name to a processor and a name in our database
            processor = ""
            if name.startswith("MTRRfix"):
                name = "IA32_MTRR_FIX" + name[len("MTRRfix") :]  # noqa
            elif name == "LBR_NHM_FROM":
                processor = "CORE1"
                name = "LASTBRANCH_0_FROM_IP"
            elif name == "LBR_NHM_TO":
                processor = "CORE1"
                name = "LASTBRANCH_0_TO_IP"
            elif name == "LBR_CORE_FROM":
                name = "LASTBRANCH_0_FROM_IP"
            elif name == "LBR_CORE_TO":
                name = "LASTBRANCH_0_TO_IP"
            elif name.startswith("P4_"):
                processor = "PENTIUM4"
                name = name[3:]
            elif name.startswith("ATOM_"):
                processor = "ATOM"
                name = name[5:]
            elif name.startswith("ARCH_LBR_"):
                name = "IA32_LBR_" + name[len("ARCH_LBR_") :]  # noqa
            elif name == "KNL_CORE_C6_RESIDENCY":
                name = name[4:]
                processor = "XEONPHI"
            elif name.startswith("IDT_"):
                processor = "IDT"
                name = name[4:]
            elif name.startswith("AMD64_"):
                processor = "AMD64"
                name = name[6:]
            elif name.startswith("CORE_PERF_FIXED_"):
                name = "IA32_" + name[10:]
            elif name.startswith("CORE_PERF_") and name != "CORE_PERF_LIMIT_REASONS":
                name = "IA32_" + name[5:]
            elif name.startswith("IA32_MCG_E") and name != "IA32_MCG_EXT_CTL":
                processor = "PENTIUM4"
                name = "MCG_R" + name[len("IA32_MCG_E") :]  # noqa
            elif name.startswith("K7_"):
                processor = "AMD64"
                name = name[3:]
                if name.startswith("EVNTSEL"):
                    name = "PERFEVTSEL" + name[len("EVNTSEL") :]  # noqa
            elif name.startswith("K8_"):
                processor = "AMD64"
                name = name[3:]
            elif name.startswith("VIA_"):
                processor = "VIA"
                name = name[4:]
            elif name.startswith("GEODE_"):
                processor = "GEODE"
                name = name[6:]
            elif name.startswith("TMTA_"):
                processor = "TRANSMETA"
                name = name[5:]
            elif name.startswith("K6_"):
                processor = "AMDK6"
                name = name[3:]
            elif name.startswith("KNC_"):
                processor = "XEONKNC"
                name = name[4:]
            elif name.startswith("ZEN2_"):
                processor = "AMD64ZEN2"
                name = name[5:]
            elif name.startswith("ZEN4_"):
                processor = "AMD64ZEN4"
                name = name[5:]
            elif name.startswith("F19H_"):
                processor = "AMD64ZEN4"
                name = name[5:]

            known_names = MSRS.msrs.get(value)
            if not known_names:
                if processor:
                    print(f"Update(MSR 0x{value:X}): new {name} with processor {processor}")
                else:
                    print(f"Update(MSR 0x{value:X}): new {name}")
                emitted_warning = True
            elif known_names.get(processor) == name:
                # Usual case: the MSR is known
                pass
            elif processor == "" and not name.startswith("IA32_") and known_names.get(processor) == "IA32_" + name:
                # The MSR is architectural but Linux does not define it with a IA32_ prefix
                pass
            elif processor == "" and name in known_names.values():
                # The MSR is known as being specific to a processor
                pass
            else:
                # List known names
                desc_names = " ".join(
                    f"{name}({prefix})" if prefix else name for prefix, name in sorted(known_names.items())
                )
                if processor:
                    print(f"Update(MSR 0x{value:X}): {name} ({processor}) (known {desc_names})")
                else:
                    print(f"Update(MSR 0x{value:X}): {name} (known {desc_names})")
                emitted_warning = True


def parse_linux_directory(linux: Path, verbose: bool = False) -> None:
    """Parse some files from Linux' git local copy"""
    with (linux / "tools/perf/pmu-events/arch/x86/mapfile.csv").open("r") as f:
        data = f.read()
    parse_perf_events_x86_mapfile(data, verbose=verbose)

    with (linux / "arch/x86/include/asm/msr-index.h").open("r") as f:
        data = f.read()
    parse_msr_define(data, verbose=verbose)

    with (linux / "tools/arch/x86/include/asm/msr-index.h").open("r") as f:
        data = f.read()
    parse_msr_define(data, verbose=verbose)


def parse_linux_from_web(verbose: bool = False) -> None:
    """Download some files from Linux' git repository"""
    url = f"{LINUX_GIT_PLAIN_URL}/tools/perf/pmu-events/arch/x86/mapfile.csv"
    if verbose:
        print(f"Downloading {url}")
    with urllib.request.urlopen(url) as response:
        data = response.read().decode("ascii")
    parse_perf_events_x86_mapfile(data, verbose=verbose)

    url = f"{LINUX_GIT_PLAIN_URL}/arch/x86/include/asm/msr-index.h"
    if verbose:
        print(f"Downloading {url}")
    with urllib.request.urlopen(url) as response:
        data = response.read().decode("ascii")
    parse_msr_define(data, verbose=verbose)

    url = f"{LINUX_GIT_PLAIN_URL}/tools/arch/x86/include/asm/msr-index.h"
    if verbose:
        print(f"Downloading {url}")
    with urllib.request.urlopen(url) as response:
        data = response.read().decode("ascii")
    parse_msr_define(data, verbose=verbose)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synchronize with Linux definitions")
    parser.add_argument("linux", nargs="?", type=Path, help="directory where Linux source is cloned (optional)")
    parser.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    args = parser.parse_args()

    if args.linux:
        parse_linux_directory(args.linux, verbose=args.verbose)
    else:
        parse_linux_from_web(verbose=args.verbose)

    sys.exit(1 if emitted_warning else 0)
