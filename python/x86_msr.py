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
"""Load x86 Model-Specific Registers (MSR) from x86_msr.txt

@author: Nicolas Iooss
@license: MIT
"""
from pathlib import Path
import re
from typing import Dict


MSR_FILE = Path(__file__).parent / "x86_msr.txt"


class x86Msrs:
    """Known x86 Model-Specific Registers"""
    def __init__(self) -> None:
        msrs: Dict[int, Dict[str, str]] = {}
        last_msr_for_prefix: Dict[str, int] = {}
        with MSR_FILE.open("r") as stream:
            for line in stream:
                try:
                    line.encode("ascii")
                except UnicodeEncodeError:
                    raise ValueError(f"Unexpected non-ASCII character in {MSR_FILE}: {line!r}")
                if "\t" in line:
                    raise ValueError(f"Unexpected TAB character in {MSR_FILE}: {line!r}")
                line = line.split("#", 1)[0].rstrip()
                if not line:
                    continue
                matches = re.match(r"^([A-Z?][0-9A-Z_]* )?0x([0-9A-F]+) ([A-Z][0-9A-Z_]+)$", line)
                if not matches:
                    raise ValueError(f"Invalid line in {MSR_FILE}: {line!r}")
                maybe_prefix, index_hex, name = matches.groups()
                prefix = maybe_prefix.rstrip() if maybe_prefix else ""
                index = int(index_hex, 16)
                if index not in msrs:
                    msrs[index] = {prefix: name}
                elif prefix not in msrs[index]:
                    msrs[index][prefix] = name
                else:
                    raise ValueError(f"Duplicate entry: {prefix!r} {index:#x} {name}")
                last_msr = last_msr_for_prefix.get(prefix, -1)
                if index <= last_msr:
                    raise ValueError(f"Sorting issue in {MSR_FILE} after {prefix!r}/{last_msr:#x}: {line!r}")
                last_msr_for_prefix[prefix] = index
        self.msrs = msrs


MSRS = x86Msrs()


if __name__ == "__main__":
    for index, names in sorted(MSRS.msrs.items()):
        for prefix, name in sorted(names.items()):
            print(f"{index:#10x} {prefix:13} {name}")
