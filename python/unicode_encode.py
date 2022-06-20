#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2014 Nicolas Iooss
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
"""Implement some Unicode encoding algorithms

Some links:
* https://codepoints.net/ Find all Unicode characters
* http://apps.timwhitlock.info/emoji/tables/unicode Emoji Unicode Tables
* https://github.com/reinderien/mimic [ab]using Unicode to create tragedy

Example of decoding the flipping table emoticon:

    $ ./unicode_encode.py '(╯°□°）╯︵ ┻━┻'
    U+  28 = UTF-8 \x28             ( (left parenthesis)
    U+256F = UTF-8 \xe2\x95\xaf     ╯ (box drawings light arc up and left)
    U+  B0 = UTF-8 \xc2\xb0         ° (degree sign)
    U+25A1 = UTF-8 \xe2\x96\xa1     □ (white square)
    U+  B0 = UTF-8 \xc2\xb0         ° (degree sign)
    U+FF09 = UTF-8 \xef\xbc\x89     ） (fullwidth right parenthesis)
    U+256F = UTF-8 \xe2\x95\xaf     ╯ (box drawings light arc up and left)
    U+FE35 = UTF-8 \xef\xb8\xb5     ︵ (presentation form for vertical left parenthesis)
    U+  20 = UTF-8 \x20               (space)
    U+253B = UTF-8 \xe2\x94\xbb     ┻ (box drawings heavy up and horizontal)
    U+2501 = UTF-8 \xe2\x94\x81     ━ (box drawings heavy horizontal)
    U+253B = UTF-8 \xe2\x94\xbb     ┻ (box drawings heavy up and horizontal)

@author: Nicolas Iooss
@license: MIT
"""
from __future__ import unicode_literals
import argparse
import math
import sys

try:
    import unicodedata
except ImportError:  # lgtm[py/unreachable-statement]
    unicodedata = None


EXAMPLES_UTF8 = [
    b'\xc2\xa0',  # U+A0 non-breaking space (NBSP)
    b'\xc2\xa9',  # U+A9 copyright sign
    b'\xc2\xab',  # U+AB left-pointing double angle quotation mark
    b'\xc2\xbb',  # U+BB right-pointing double angle quotation mark
    b'\xc3\xa9',  # U+E9 Latin small letter E with acute
    b'\xc7\x83',  # U+1C3 Latin letter retroflex click (!)
    b'\xce\xa9',  # U+3A9 Greek capital letter Omega
    b'\xe2\x80\xa2',  # U+2022 bullet
    b'\xe2\x80\xbd',  # U+203D interrobang
    b'\xe2\x80\x8b',  # U+200B zero width space (ZWSP)
    b'\xe2\x80\x8c',  # U+200C zero width non-joiner (ZWNJ)
    b'\xe2\x80\x8d',  # U+200C zero width joiner (ZWJ)
    b'\xe2\x80\x8e',  # U+200F left-to-right mark (LRM)
    b'\xe2\x80\x8f',  # U+200F right-to-left mark (RLM)
    b'\xe2\x82\xac',  # U+20AC euro sign
    b'\xe2\x86\x92',  # U+2192 rightwards arrow
    b'\xe2\x87\x92',  # U+21D2 rightwards double arrow
    b'\xe2\x88\x9e',  # U+221E infinity
    b'\xe2\x98\x80',  # U+2605 black sun with rays
    b'\xe2\x98\x85',  # U+2605 black star
    b'\xe2\x88\x95',  # U+2215 division slash
    b'\xe2\x98\x90',  # U+2610 ballot box
    b'\xe2\x98\x91',  # U+2611 ballot box with check
    b'\xe2\x98\xa2',  # U+2622 radioactive sign
    b'\xe2\x98\xba',  # U+263A white smiling face
    b'\xe2\x99\xa5',  # U+2665 black heart suit
    b'\xe2\x9a\xa0',  # U+26A0 warning sign
    b'\xef\xbb\xbf',  # U+FEFF byte order mark (BOM, zero width no-break space)
    b'\xef\xbf\xbd',  # U+FFFD replacement character
    b'\xf0\x9f\x8e\x89',  # U+1F389 party popper (:tada:)
    b'\xf0\x9f\x98\x87',  # U+1F607 smiling face with halo (angel)
    b'\xf0\x9f\x90\xa7',  # U+1F427 penguin
    b'\xf0\x9f\x91\x8c',  # U+1F44C ok hand sign
    b'\xf0\x9f\x91\x8d',  # U+1F44D thumbs up sign
    b'\xf0\x9f\x96\x92',  # U+1F592 reversed thumbs up sign ("like")
    b'\xf0\x9f\x98\x8a',  # U+1F60A smiling face with smiling eyes
    b'\xf0\x9f\x9a\x80',  # U+1F680 rocket
    b'\xf0\x9f\xa4\x97',  # U+1F917 hugging face
]


def get_utf8_bytes(char):
    """Get the UTF-8 bytes encoding an unicode character

    Parameters:
        char: unicode character

    Returns: integer array of the UTF-8 encoding
    """
    # Get the codepoint (integer between 0 and 0x1fffff)
    c = ord(char)
    assert c < 0x20000
    if c < 0x80:
        # 0..7F -> 00..7F (ASCII)
        return [c]
    elif c < 0x800:
        # 80..FF -> C2..C3 + 1 (ISO-8859-1 = Latin 1)
        # 100..7FF -> C4..DF + 1
        return [0xc0 + (c >> 6), 0x80 + (c & 0x3f)]
    elif c < 0x10000:
        # 800..FFF -> E0 + 2
        # 1000..FFFF -> E1..EF + 2
        return [0xe0 + (c >> 12), 0x80 + ((c >> 6) & 0x3f), 0x80 + (c & 0x3f)]
    else:
        # 10000..FFFFF -> F0..F3 + 3
        # 100000..1FFFFF -> F4..F7 + 3
        return [
            0xf0 + (c >> 18),
            0x80 + ((c >> 12) & 0x3f),
            0x80 + ((c >> 6) & 0x3f),
            0x80 + (c & 0x3f)]


if sys.version_info >= (3,):
    def get_utf8_bytes_native(char):
        return [int(b) for b in char.encode('utf-8')]
else:
    def get_utf8_bytes_native(char):
        return [ord(b) for b in char.encode('utf-8')]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Show character encoding")
    parser.add_argument('chars', nargs='*',
                        help="to-be-encoded UTF-8 characters")

    args = parser.parse_args(argv)

    if sys.version_info >= (3,):
        characters = ' '.join(args.chars)
        # Use binary stdout to avoid issues with pure ascii output and weird
        # work-arounds such as setting PYTHONIOENCODING=UTF-8
        stdout = sys.stdout.buffer
    else:
        characters = b' '.join(args.chars).decode('utf-8')
        stdout = sys.stdout
    if not characters:
        characters = b''.join(EXAMPLES_UTF8).decode('utf-8')

    # Get the maximal numeric representation to get the digit count
    maxnum = max(ord(c) for c in characters)
    n = int(math.ceil(math.log(maxnum, 16)))
    pattern = 'U+{0:' + str(n) + 'X} = UTF-8 {1:16s} {2}'

    for char in characters:
        byteints = get_utf8_bytes(char)
        assert byteints == get_utf8_bytes_native(char)
        hexa = ''.join('\\x{0:02x}'.format(b) for b in byteints)
        line = pattern.format(ord(char), hexa, char)
        if unicodedata is not None:
            try:
                line += ' ({0})'.format(unicodedata.name(char).lower())
            except ValueError:
                pass
        stdout.write((line + '\n').encode('utf-8'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
