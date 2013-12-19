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
"""Normalize Unicode data

This program may normalize strings using Python standard library

Doc: http://docs.python.org/3/library/unicodedata.html#unicodedata.normalize

@author: Nicolas Iooss
@license: MIT
"""
import argparse
import logging
import unicodedata
import sys


logger = logging.getLogger(__name__)


def normalize(unistr, form='NFKD', toascii=False):
    """Return normal form of unistr"""
    # Python 2 needs unicode strings
    if sys.version_info < (3,):
        unistr = unistr.decode('utf8')

    normstr = unicodedata.normalize(form, unistr)
    if toascii:
        # Encode unicode to ASCII bytes and return a string
        return normstr.encode('ascii', errors='ignore').decode('ascii')
    else:
        # Encode unicode to bytes and return ASCII string
        ret = repr(normstr.encode('utf8'))
        # Remove single quotes
        return ret[2:-1] if ret.startswith('b\'') else ret[1:-1]


def iter_normalize(unistrs, form='NFKD', toascii=False):
    """Iterate over unistrs and normalize each item"""
    for unistr in unistrs:
        yield normalize(unistr, form, toascii)


def main(argv=None):
    """Parse command line arguments and print normalized strings"""
    parser = argparse.ArgumentParser(description="Normalize Unicode strings")
    parser.add_argument('strings', nargs='+',
                        help="text to normalize")
    parser.add_argument('-a', '--ascii', action='store_true',
                        help="convert to ASCII")
    parser.add_argument('-f', '--form', default='NFKD',
                        help="unicode normal form (NFKD by default)")
    parser.add_argument('-l', '--lines', action='store_true',
                        help="print one argument per line")

    args = parser.parse_args(argv)

    if args.form not in ('NFC', 'NFD', 'NFKC', 'NFKD'):
        logger.warning("Unknown normal form '{}'".format(args.form))

    normalized = iter_normalize(args.strings, args.form, args.ascii)
    if args.lines:
        for text in normalized:
            print(text)
    else:
        print(' '.join(normalized))
    return 0


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
