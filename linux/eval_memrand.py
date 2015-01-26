#!/usr/bin/env python
# -*- coding:UTF-8 -*-
"""Evaluate the randomness of memory addresses

This program uses "cat /proc/self/maps" to retrieve the addresses of
interesting memory regions like stack, vDSO...
It agregates the addresses to evaluate their randomness.
"""
import argparse
import re
import subprocess
import sys


def bit_count(num):
    """Count the bit which are set in num"""
    num = (num & 0x5555555555555555) + ((num & 0xAAAAAAAAAAAAAAAA) >> 1)
    num = (num & 0x3333333333333333) + ((num & 0xCCCCCCCCCCCCCCCC) >> 2)
    num = (num & 0x0F0F0F0F0F0F0F0F) + ((num & 0xF0F0F0F0F0F0F0F0) >> 4)
    num = (num & 0x00FF00FF00FF00FF) + ((num & 0xFF00FF00FF00FF00) >> 8)
    num = (num & 0x0000FFFF0000FFFF) + ((num & 0xFFFF0000FFFF0000) >> 16)
    num = (num & 0x00000000FFFFFFFF) + ((num & 0xFFFFFFFF00000000) >> 32)
    return num


class RandomAddress(object):
    """Represent a aggregate of a set of values for a given random address"""

    def __init__(self):
        self.and_bits = -1
        self.or_bits = 0
        self.bitcount = [0] * 64

    def add(self, addr):
        """Add a new value of random address"""
        self.and_bits &= addr
        self.or_bits |= addr
        bitval = 1
        bitidx = 0
        while bitval <= addr:
            if bitval & addr:
                self.bitcount[bitidx] += 1
            bitval *= 2
            bitidx += 1

    def get_stat(self, total_count):
        """Get a string representation of the overall statistics"""
        # Compute the mask according to this table:
        # /-----------+-----+----+-----------------\
        # | bit value | and | or | randomness mask |
        # +-----------+-----+----+-----------------+
        # | always 0  |  0  |  0 |        0        |
        # | random    |  0  |  1 |        1        |
        # | always 1  |  1  |  1 |        0        |
        # \-----------+-----+----+-----------------/
        rmask = (~self.and_bits) & self.or_bits
        if rmask == 0:
            return 'not random, always {}'.format(hex(self.and_bits)[2:])

        xmin = hex(self.and_bits)[2:]
        xmax = hex(self.or_bits)[2:]
        if len(xmin) < len(xmax):
            xmin = '0' * (len(xmax) - len(xmin)) + xmin
        xmask = [x if x == y else 'X' for x, y in zip(xmin, xmax)]

        # Find out "weak" random bits
        quite_weak = []
        very_weak = []
        for bitidx, cnt in enumerate(self.bitcount):
            if cnt != 0 and cnt != total_count:
                percent = 100 * cnt // total_count
                if not 10 < percent < 90:
                    very_weak.append('{}({}%)'.format(bitidx, percent))
                    # Mark very weak bits as W in the hexadecimal mask
                    xmask[-(bitidx // 4) - 1] = 'W'
                elif not 30 < percent < 70:
                    quite_weak.append('{}({}%)'.format(bitidx, percent))
                    # Mark weak bits as w in the hexadecimal mask
                    xmask[-(bitidx // 4) - 1] = 'w'

        description = '{} ({}-{}), {} random bits'.format(
            ''.join(xmask), xmin, xmax, bit_count(rmask))
        if len(quite_weak):
            description += '\n  {} quite weak bits: {}'.format(
                len(quite_weak), ', '.join(quite_weak))
        if len(very_weak):
            description += '\n  {} very weak bits: {}'.format(
                len(very_weak), ', '.join(very_weak))
        return description


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Evaluate the randomness of memory addresses")
    parser.add_argument('-n', '--num', type=int, default=1000,
                        help="number of execution to perfom")
    args = parser.parse_args(argv)

    cmdline = ['cat', '/proc/self/maps']
    mappings = {}

    # First run, to initialize what can be found
    proc = subprocess.Popen(cmdline, stdout=subprocess.PIPE)
    for line in proc.stdout:
        sline = line.decode('ascii', errors='ignore').strip().split()
        # Ignore anonymous mappings
        if len(sline) < 6:
            continue
        path = sline[5].strip()
        if not path:
            continue

        if path[0] == '[' and path[-1] == ']':
            # Add kernel mappings, like [heap], [stack] and [vdso]
            mappings[path] = RandomAddress()
        elif re.match(r'/(.*/)?lib.*/libc(-[^/]*)?\.so', path):
            # Add a mapping to libc, if found
            mappings[path] = RandomAddress()
        elif re.match(r'/(.*/)?lib.*/ld(-[^/]*)?\.so', path):
            # Add a mapping to ld.so, if found
            mappings[path] = RandomAddress()
    retval = proc.wait()
    if retval:
        return retval
    del proc

    # Run
    numiter = max(args.num, 1)
    print("Iterating {} times".format(numiter))
    for _ in range(numiter):
        has_mapping = dict((path, False) for path in mappings.keys())

        proc = subprocess.Popen(cmdline, stdout=subprocess.PIPE)
        for line in proc.stdout:
            sline = line.decode('ascii', errors='ignore').strip().split()
            if len(sline) < 6:
                continue
            path = sline[5]
            if has_mapping.get(path) is False:
                addr = int(sline[0].split('-')[0], 16)
                has_mapping[path] = True
                mappings[path].add(addr)

        # Wait for the process
        retval = proc.wait()
        if retval:
            return retval
        del proc
        if any(val is False for val in has_mapping.values()):
            missing = [name for (name, val) in has_mapping.items() if not val]
            sys.stderr.write("Missing: {} :(\n".format(', '.join(missing)))
            return 1

    # Display results
    for name in sorted(mappings.keys()):
        print("{}: {}".format(name, mappings[name].get_stat(numiter)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
