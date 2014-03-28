#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2013 Nicolas Iooss
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
"""Read the partition table of a MSDOS-formatted partition

@author: Nicolas Iooss
@license: MIT
"""
import argparse
import struct
import sys


def decode_chs(chsdata):
    """Decode a Cylinder, Head, Sector address"""
    assert len(chsdata) == 3
    b1, b2, b3 = [int(b) for b in chsdata]
    return ((b2 & 0xc0) << 2) | b3, b1, b2 & 0x3f


def get_human_size(size):
    """Return a string describing the size in bytes"""
    if size < 1024:
        return '{} B'.format(size)
    if size < 1024 * 1024:
        return '{:.2f} KB'.format(float(size) / 1024)
    if size < 1024 * 1024 * 1024:
        return '{:.2f} MB'.format(float(size) / (1024 * 1024))
    if size < 1024 * 1024 * 1024 * 1024:
        return '{:.2f} GB'.format(float(size) / (1024 * 1024 * 1024))
    return '{:.2f} TB'.format(float(size) / (1024 * 1024 * 1024 * 1024))


def print_partition(partdata, partnum):
    """Describe the 16 bytes of partdata into a printed message"""
    assert len(partdata) == 16

    # Detect empty partitions
    if not any(b for b in partdata):
        print("Partition {}: empty".format(partnum))
        return True

    flags = int(partdata[0])
    chs_first = decode_chs(partdata[1:4])
    parttype = int(partdata[4])
    chs_last = decode_chs(partdata[5:8])
    lba = struct.unpack('<I', partdata[8:12])[0]
    numsectors = struct.unpack('<I', partdata[12:16])[0]

    print("Partition {}:".format(partnum))
    print("    flags {:02x}h{} type {:02x}h{}".format(
        flags, " (active)" if flags & 0x80 else "",
        parttype, " (extended)" if parttype == 5 else ""))
    print("    {} sectors from LBA {} ({})".format(
        numsectors, lba, get_human_size(numsectors * 512)))

    if chs_first == (1023, 254, 63):
        if chs_last != (1023, 254, 63):
            print("    Invalid CHS addresses: {} and {}".format(
                chs_first, chs_last))
    elif chs_last == (1023, 254, 63):
        print("    CHS first {}, last too big".format(chs_first))
        # Check if geometry is (63 SPT, 255 HPC)
        c1, h1, s1 = chs_first
        lba_from_chs = ((c1 * 255) + h1) * 63 + (s1 - 1)
        if lba_from_chs == lba:
            print("    Geometry: 63 sectors/track, 255 heads/cylinder")
        else:
            print("    Unknown disk geometry")
    else:
        print("    CHS first {}, last {}".format(chs_first, chs_last))

        # Find geometry using this formula:
        # LBA = ((C * HPC) + H) * SPT + (S - 1)
        c1, h1, s1 = chs_first
        c2, h2, s2 = chs_last
        const1 = lba - s1 + 1
        const2 = lba + numsectors - s2
        denom = c1 * h2 - c2 * h1
        if denom == 0:
            print("    Unable to guess geometry (singular equations)")
        else:
            spt = (c1 * const2 - c2 * const1) // denom
            hpc_spt = (const1 * h2 - const2 * h1) // denom
            if spt < 0 or hpc_spt < 0 or hpc_spt % spt != 0:
                print("    Unable to guess geometry (unrealistic constants)")
            else:
                print("    Geometry: {} sectors/track, {} heads/cylinder"
                      .format(spt, hpc_spt // spt))


def print_parttable(sector, filename=None):
    """Print the partition table given with a "sector" (at least 512 bytes)"""
    error_prefix = "Error from input" if filename is None \
        else "Error from '{}'".format(filename)
    # Sanity checks
    if len(sector) < 512:
        sys.stderr.write("{}: not enough data\n".format(error_prefix))
        return False
    if sector[510:512] != b'\x55\xaa':
        sys.stderr.write("{}: invalid magic number\n".format(error_prefix))
        return False

    # Extract partitions
    if filename is not None:
        print("{}:".format(filename))
    print_partition(sector[446:462], 1)
    print_partition(sector[462:478], 2)
    print_partition(sector[478:494], 3)
    print_partition(sector[494:510], 4)
    return True


def main(argv=None):
    """Program entry point"""
    parser = argparse.ArgumentParser(description="Read partition table")
    parser.add_argument('files', metavar='FILES', nargs='*',
                        help="Boot record files (read standard input if none)")

    args = parser.parse_args(argv)
    retval = 0
    if args.files:
        for ifile, filename in enumerate(args.files):
            if ifile != 0:
                print("")
            with open(filename, 'rb') as fd:
                sector = fd.read(512)
                if not print_parttable(sector, filename):
                    retval = 1
    else:
        if sys.version_info >= (3,):
            sector = sys.stdin.buffer.read(512)
        else:
            sector = bytes(sys.stdin.read(512))
        if not print_parttable(sector):
            retval = 1
    return retval


if __name__ == '__main__':
    sys.exit(main())
