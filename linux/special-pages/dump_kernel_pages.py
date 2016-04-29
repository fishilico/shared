#!/usr/bin/env python
# -*- coding:UTF-8 -*-
"""Extract all special pages mapped by Linux kernel into process memory"""
import ctypes
import ctypes.util
import errno
import sys


if sys.version_info < (2, 7):
    sys.stderr.write("This program cannot be run in Python<2.7 mode.\n")
    sys.exit(0)


libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
libc.write.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
libc.write.restype = ctypes.c_ssize_t


def is_kernel_addr(addr):
    if sys.maxsize > 2**32:
        # 64-bit kernels always have the high bit set
        return addr >= 2**63
    else:
        # 32-bit kernels may start at 0xc0000000 but each user-exposed page
        # lies above 0xffff0000
        return addr >= 0xffff0000


def raw_write(fileout, addr, size):
    """Write a raw buffer into a file"""
    while size > 0:
        count = libc.write(fileout.fileno(), addr, size)
        if count < 0:
            if ctypes.get_errno() != errno.EFAULT:
                raise OSError(ctypes.get_errno())
            # There was a fault while reading the address.
            # This may be caused by kernel addresses readable in userspace
            if is_kernel_addr(addr):
                data = (ctypes.c_byte * size)()
                ctypes.memmove(data, ctypes.c_void_p(addr), size)
                count = fout.write(data)
                # In Python2 count is None and in Python3 count is size
                assert count is None or count == size
            else:
                # This happens while reading vvar on Gentoo Hardened.
                # Truncate the file.
                print("... Unable to read {} bytes from {:x}".format(
                    size, addr))
            return

        assert count <= size
        addr += count
        size -= count


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

        # Write the pages to a file
        filename = 'kernel-{}.out'.format(name)
        print("{}: {:x}..{:x} {}".format(filename, addr1, addr2, sline[1]))
        with open(filename, 'wb') as fout:
            raw_write(fout, addr1, addr2 - addr1)
