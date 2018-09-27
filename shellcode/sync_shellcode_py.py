#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2015 Nicolas Iooss
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
"""
Synchronize the shellcodes in *.S files with those in shellcode.py

@author: Nicolas Iooss
@license: MIT
"""
import re
import os
import os.path
import struct
import sys

from shellcode import normalize_arch


def extract_shc_from_asm(asmfile, is_littleendian):
    """Extract a binary shellcode from the hexadecimal comments of a .S file"""
    format_for_hexsize = {
        2: 'B',
        4: 'H',
        8: 'I',
    }
    with open(asmfile, 'r') as fasm:
        for line in fasm:
            matches = re.match(r'    /\* ([0-9a-f ]+)\*/', line)
            if matches is not None:
                for hexnum in matches.group(1).split():
                    yield struct.pack(
                        ('<' if is_littleendian else '>') +
                        format_for_hexsize[len(hexnum)],
                        int(hexnum, 16))


def split_repr(data, cols):
    """Split the binary representation of data to fit the given number of cols
    """
    rep = repr(data)
    if len(rep) <= cols:
        return rep, None

    # Do a dichotomy to find an index where to cut the data
    min_idx = 1
    max_idx = min(cols, len(data) - 1)
    while min_idx != max_idx:
        # Sanity checks
        assert min_idx < max_idx
        assert len(repr(data[:min_idx])) <= cols
        assert len(repr(data[:max_idx + 1])) > cols

        cur = (min_idx + max_idx + 1) // 2
        rep = repr(data[:cur])
        if len(rep) <= cols:
            min_idx = cur
        elif len(rep) > cols:
            max_idx = cur - 1

    return repr(data[:min_idx]), data[min_idx:]


def split_reprbytes(data, cols):
    """Same as split_repr(), but force a b prefix"""
    if sys.version_info < (3,):
        reprshc, shc = split_repr(data, cols - 1)
        return 'b' + reprshc, shc
    return split_repr(data, cols)


def sync_shellcode_py():
    # Extract binary code from every .S file
    shellcodes = {}
    for filename in os.listdir(os.path.dirname(__file__)):
        if filename == 'multiarch_linux.S':
            continue
        if filename.endswith('.S'):
            osname, arch = filename[:-2].split('_', 1)
            osname = osname[0].upper() + osname[1:]
            arch = normalize_arch(arch)
            bincode = b''.join(extract_shc_from_asm(filename, True))
            shellcodes[osname + '.' + arch] = bincode

    # Update shellcode.py
    newlines = []
    with open('shellcode.py', 'r') as fsh:
        # Copy until the marker
        for line in fsh:
            newlines.append(line)
            if line == 'SHELLCODES = {\n':
                break
        else:
            sys.stderr.write("Unable to find 'SHELLCODES = {' marker!\n")
            return False

        # Introduce new lines
        for key in sorted(shellcodes):
            shc = shellcodes[key]
            newlines.append("    # {0} bytes\n".format(len(shc)))
            newlines.append("    '{0}':\n".format(key))
            # Cut the representation
            reprshc, shc = split_reprbytes(shc, 69)
            while shc is not None:
                newlines.append('        {0} +\n'.format(reprshc))
                reprshc, shc = split_reprbytes(shc, 69)
            newlines.append('        {0},\n'.format(reprshc))

        # Skip old lines
        for line in fsh:
            if line == '}\n':
                newlines.append(line)
                break
        else:
            sys.stderr.write("Unable to find '}' marker!\n")
            return False

        # Copy the remaining of the file
        newlines += list(fsh)
    with open('shellcode.py', 'w') as fsh:
        fsh.write(''.join(newlines))
    return True


if __name__ == '__main__':
    sys.exit(0 if sync_shellcode_py() else 1)
