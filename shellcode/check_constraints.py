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
"""Check some contraints of the shellcodes written in shellcode.py

More precisely, check the scanf" constraints: no \r, \n, \0 nor space in any
shellcode sequence.

@author: Nicolas Iooss
@license: MIT
"""
import shellcode


class CheckError(Exception):

    def __init__(self, message):
        super(CheckError, self).__init__(message)
        self.message = message


def check_shellcode(shc):
    """Check a given shellcode against some constraints"""
    if b'\0' in shc:
        raise CheckError("contains nul characters")
    if b'\r' in shc:
        raise CheckError("contains carriage return characters")
    if b'\n' in shc:
        raise CheckError("contains newline characters")
    if b' ' in shc:
        raise CheckError("contains space characters")


def check_all_shellcodes():
    """Check all shellcodes from shellcode.py"""
    retval = True
    for plat_id, shc in sorted(shellcode.SHELLCODES.items()):
        print("Checking {0} ({1} bytes)".format(plat_id, len(shc)))
        try:
            check_shellcode(shc)
        except CheckError as exc:
            print("Error in shellcode for {0}: {1}".format(
                plat_id, exc.message))
            retval = False
    return retval


if __name__ == '__main__':
    import sys
    sys.exit(0 if check_all_shellcodes() else 1)
