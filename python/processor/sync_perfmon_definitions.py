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
"""Extract information from Intel perfmon source code"""
import argparse
import re
import sys
import urllib.request
from pathlib import Path
from typing import FrozenSet, List, Optional, Tuple

from cpu_model import CPU_MODELS


INTEL_PERFMON_GIT_RAW_URL = "https://github.com/intel/perfmon/raw/main"

# Known associations between abbrevation in perfmon and abbreviation in the database
KNOWN_PERFMON_ABBREV: FrozenSet[Tuple[str, str]] = frozenset(
    (
        ("ADL", "ADL-N"),
        ("ADL", "ADL-P"),
        ("ADL", "RPL-P"),
        ("ADL", "RPL-S"),
        ("BDW", "BDW-G"),
        ("CLX", "CLX-SP"),
        ("EHL", "JSL"),
        ("GLP", "GLK"),
        ("GNR", "GNR-D"),
        ("GNR", "GNR-X"),
        ("ICL", "ICL-U/Y"),
        ("ICX", "ICL"),
        ("ICX", "ICXD"),
        ("IVT", "IVBX"),
        ("JKT", "SNBX"),
        ("KNL", "PHI KNL"),
        ("KNM", "PHI KNM"),
        ("MTL", "MTL-S"),
        ("RKL", "RKL-S"),
        ("SKL", "CML"),
        ("SKL", "KBL"),
        ("SLM", "SLM/AMT"),
        ("SPR", "EMR-X"),
        ("SPR", "SPR-X"),
        ("TGL", "TGL-H"),
    )
)

# Known associations between filename and model name
KNOWN_FILENAME_MODEL: FrozenSet[Tuple[str, str]] = frozenset(
    (
        ("Bonnell", "Atom Bonnel, Atom Saltwell Mid"),
        ("Bonnell", "Atom Bonnel, Atom Saltwell Tablet"),
        ("Bonnell", "Atom Bonnel, Atom Saltwell"),
        ("Bonnell", "Atom Bonnell Mid"),
        ("Bonnell", "Atom Bonnell"),
        ("Jaketown", "Sandy Bridge Xeon"),
        ("KnightsLanding", "Xeon Phi Knights Landing"),
        ("KnightsLanding", "Xeon Phi Knights Mill"),
        ("NehalemEP", "Nehalem EP"),
        ("NehalemEP", "Nehalem"),
        ("NehalemEX", "Nehalem-EX"),
        ("Silvermont", "Atom Merrifield , Atom Silvermont Mid"),
        ("Silvermont", "Atom Silvermont D"),
        ("Silvermont", "Atom Silvermont"),
        ("Silvermont", "Atom Silvermont, Atom Airmont Mid"),
        ("Silvermont", "Atom Silvermont, Atom Airmont"),
        ("WestmereEP-DP", "Westmere DP"),
        ("WestmereEP-SP", "Westmere"),
        ("WestmereEX", "Westmere-EX"),
        ("alderlake", "Alder Lake N"),
        ("alderlake", "Alder Lake P"),
        ("alderlake", "Alder Lake"),
        ("alderlake", "Raptor Lake-P"),
        ("alderlake", "Raptor Lake-S"),
        ("broadwell", "Broadwell"),
        ("broadwell", "Broadwell-G"),
        ("broadwellde", "Broadwell Xeon DE"),
        ("broadwellx", "Broadwell Xeon"),
        ("cascadelakex", "Cascade Lake Server"),
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
        ("icelakex", "Ice Lake Xeon D"),
        ("icelakex", "Ice Lake"),
        ("ivybridge", "Ivy Bridge"),
        ("ivytown", "Ivy Bridge Xeon"),
        ("meteorlake", "Meteor Lake"),
        ("meteorlake", "Meteor Lake-S"),
        ("rocketlake", "Rocket Lake"),
        ("sandybridge", "Sandy Bridge"),
        ("sapphirerapids", "Emerald Rapids Xeon"),
        ("sapphirerapids", "Sapphire Rapids Xeon"),
        ("sierraforest", "Sierra Forest Xeon"),
        ("skylake", "Comet Lake"),
        ("skylake", "Kaby Lake"),
        ("skylake", "Skylake"),
        ("skylake", "Skylake-L"),
        ("skylakex", "Skylake Server"),
        ("snowridgex", "Snow Ridge, Atom Tremont X"),
        ("tigerlake", "Tiger Lake"),
    )
)

emitted_warning = False


def parse_perf_events_x86_mapfile(content: str, verbose: bool = False) -> None:
    """Parse mapfile.csv"""
    global emitted_warning
    for line in content.splitlines():
        if line == "Family-model,Version,Filename,EventType,Core Type,Native Model ID,Core Role Name":
            # Skip the header
            continue
        # Match "GenuineIntel-6-2E,V3,/NHM-EX/events/NehalemEX_core.json,core,,,"
        # and "GenuineIntel-6-55-[01234],V1.30,/SKX/events/skylakex_core.json,core,,,"
        matches = re.match(
            r"^(GenuineIntel)-(6)-([0-9A-F\[\]-]+),V[0-9.]+,/([A-Z-]+)/events/([A-Za-z_-]+)\.json,([ a-z_]+),[0-9x]*,[0-9x]*,(?:|Atom|Core)$",
            line,
        )
        if not matches:
            raise ValueError(f"Unexpected line in mapfile.csv: {line!r}")
        vendor, fam_str, model_str, abbrev_from_map, filename, name_suffix = matches.groups()
        family = int(fam_str)

        if name_suffix == "hybridcore":
            name_suffix = "_core"
        elif name_suffix == "offcore":
            name_suffix = "_matrix"
        else:
            name_suffix = "_" + name_suffix.replace(" ", "_")
        if not filename.endswith(name_suffix):
            raise ValueError(f"Unexpected file name without the right suffix: {line!r}")
        filename = filename[: -len(name_suffix)]

        # Remove filename suffix
        if filename in {"alderlake_gracemont", "alderlake_goldencove"}:
            filename = "alderlake"
        elif filename in {"meteorlake_crestmont", "meteorlake_redwoodcove"}:
            filename = "meteorlake"

        cpu_models = CPU_MODELS.get(vendor, {}).get(family)
        if cpu_models is None:
            print(f"Warning(mapfile, {line!r}): unknown {vendor} family {family}")
            emitted_warning = True
            continue
        # The stepping is specific with model 55
        cpuid_data: List[Tuple[int, Optional[List[Optional[str]]]]]
        if model_str.startswith("55-"):
            if model_str == "55-[01234]":
                cpuid_data = [(0x55, cpu_models.get((0x55, 0)))]
            elif model_str == "55-[56789ABCDEF]":
                cpuid_data = [(0x55, cpu_models.get((0x55, 5)))]
            else:
                print(f"Warning(mapfile, {line!r}): stepping for model 0x55")
                emitted_warning = True
                continue
        elif re.match(r"^[0-9A-F][0-9A-F]$", model_str):
            # The model is explicitly given
            model = int(model_str, 16)
            cpuid_data = [(model, cpu_models.get((model, -1)))]
        else:
            print(f"Warning(mapfile, {line!r}): Unsupported {model_str}")
            emitted_warning = True
            continue

        for model, model_data in cpuid_data:
            if model_data is None:
                print(f"Warning(mapfile, {line!r}): Unknown model {model:#04x}")
                continue
            abbrev = model_data[0]
            name = model_data[1]
            if abbrev_from_map != abbrev and (abbrev_from_map, abbrev) not in KNOWN_PERFMON_ABBREV:
                print(
                    f"Warning(mapfile, {line!r}): missing abbreviation association in known list {(abbrev_from_map, abbrev)!r}"
                )
                emitted_warning = True
            if verbose:
                print(f"{model:#04x}: {abbrev_from_map:9}/{filename:22} {abbrev or '?':7} {name}")
            # Strip parenthesis from the name
            assert name is not None
            while m := re.match(r"^(.* )\([^)]*\)(.*)$", name):
                name = (m.group(1) + m.group(2)).strip()
            if (filename, name) not in KNOWN_FILENAME_MODEL:
                print(f"Warning(mapfile, {line!r}): missing association in known list {(filename, name)!r}")
                emitted_warning = True


def parse_perfmon_directory(perfmon: Path, verbose: bool = False) -> None:
    """Parse some files from Perfmon' git local copy"""
    with (perfmon / "mapfile.csv").open("r") as f:
        data = f.read()
    parse_perf_events_x86_mapfile(data, verbose=verbose)


def parse_perfmon_from_web(verbose: bool = False) -> None:
    """Download some files from Perfmon' git repository"""
    # Download https://github.com/intel/perfmon/blob/main/mapfile.csv
    url = f"{INTEL_PERFMON_GIT_RAW_URL}/mapfile.csv"
    if verbose:
        print(f"Downloading {url}")
    with urllib.request.urlopen(url) as response:
        data = response.read().decode("ascii")
    parse_perf_events_x86_mapfile(data, verbose=verbose)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synchronize with Perfmon definitions")
    parser.add_argument("perfmon", nargs="?", type=Path, help="directory where Perfmon source is cloned (optional)")
    parser.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    args = parser.parse_args()

    if args.perfmon:
        parse_perfmon_directory(args.perfmon, verbose=args.verbose)
    else:
        parse_perfmon_from_web(verbose=args.verbose)

    sys.exit(1 if emitted_warning else 0)
