#!/usr/bin/env python
# -*- coding:UTF-8 -*-
"""Extract Linux vDSO memory directly from the running process

vDSO = virtual dynamic shared object
"""
import os
import sys


out_filename = sys.argv[1] if len(sys.argv) >= 2 else 'linux-vdso.so'

addr_range = None
with open('/proc/self/maps', 'r') as fmaps:
    for line in fmaps:
        sline = line.split()
        if len(sline) >= 6 and sline[-1] == '[vdso]':
            addr_range = sline[0]
            break

if addr_range is None:
    sys.stderr.write("No vdso found in /proc/self/maps\n")
    sys.exit(1)

addr1, addr2 = [int(addr, 16) for addr in addr_range.split('-', 1)]
with open('/proc/self/mem', 'rb') as fmem:
    with open(out_filename, 'wb') as fout:
        fmem.seek(addr1, os.SEEK_SET)
        fout.write(fmem.read(addr2 - addr1))
print("vDSO written to {}".format(out_filename))
