#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
"""Utility functions to decode an AVR firmware"""
import struct
import sys


def load_ihex(filepath):
    """Load an IHEX file and return a bytes with its content"""
    memory = bytearray(0x10000)
    max_addr = 0
    with open(filepath, 'r') as fihex:
        for line in fihex:
            if not line.startswith(':'):
                sys.stderr.write("Invalid line in IHEX: {}\n".format(line))
                return
            linebin = bytes.fromhex(line[1:].rstrip())

            # Decode line header
            size, addr, is_end = struct.unpack('>BHB', linebin[:4])

            # Verify checksum and line size
            if sum(linebin) & 0xff:
                sys.stderr.write("Invalid IHEX checksum in: {}\n".format(line))
                return
            if len(linebin) != 4 + size + 1:
                sys.stderr.write("Invalid IHEX size in: {}\n".format(line))
                return

            # Interpret line
            if is_end:
                break
            memory[addr:addr + size] = linebin[4:-1]
            if addr + size > max_addr:
                max_addr = addr + size
    return bytes(memory[:max_addr])


def check_labels_order(labels):
    """Check the order of a label definition list"""
    for idx, lab in enumerate(labels[:-1]):
        nextlab = labels[idx + 1]
        if lab.addr < nextlab.addr:
            continue
        if lab.addr == nextlab.addr and nextlab.labtype == 'c':
            continue
        if lab.labtype != 'R' and nextlab.labtype == 'R':
            continue
        sys.stderr.write("Invalid label ordering between {} and {}\n"
                         .format(lab, nextlab))
        return False
    return True
