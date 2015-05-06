#!/usr/bin/env python
# -*- coding:UTF-8 -*-
"""Extract all special pages mapped by Linux kernel into process memory"""
import ctypes
import sys


if sys.version_info < (2, 7):
    sys.stderr.write("This program cannot be run in Python<2.7 mode.\n")
    sys.exit(0)


# Enumerate memory ranges with /proc/self/maps
with open('/proc/self/maps', 'r') as fmaps:
    for line in fmaps:
        sline = line.split()

        # Find special pages such as [vvar], [vdso], [vectors]...
        if len(sline) < 6 or sline[-1][0] != '[' or sline[-1][-1] != ']':
            continue
        name = sline[-1][1:-1]
        if name in ('stack', 'heap'):
            continue

        # Retrieve the pages
        addr1, addr2 = [int(addr, 16) for addr in sline[0].split('-', 1)]
        assert addr1 < addr2
        data = (ctypes.c_byte * (addr2 - addr1))()
        ctypes.memmove(data, ctypes.c_void_p(addr1), addr2 - addr1)

        # Save file
        filename = 'kernel-{}.out'.format(name)
        print("{}: {:x}..{:x} {}".format(filename, addr1, addr2, sline[1]))
        with open(filename, 'wb') as fout:
            fout.write(data)
