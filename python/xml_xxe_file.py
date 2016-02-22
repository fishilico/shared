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
"""Show the content of a file with an XML external entity (XXE)

@author: Nicolas Iooss
@license: MIT
"""
import argparse
import os.path
import sys
import xml.sax
import xml.sax.saxutils


if sys.version_info >= (3,):
    from io import BytesIO
else:
    try:
        from cStringIO import StringIO as BytesIO
    except ImportError:
        from StringIO import StringIO as BytesIO


XML_FILE = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE file [<!ENTITY xxe SYSTEM "file://{filepath}" >]>\n'
    '<file path="{filepath}">\n&xxe;</file>'
    )


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read a file with XML external entity (XXE)")
    parser.add_argument('file', nargs='?', default='/etc/shells',
                        help="file to be read")
    parser.add_argument('-l', '--lxml', action='store_true',
                        help="use lxml")
    parser.add_argument('-n', '--noxxe', action='store_true',
                        help="disable XXE expansion feature")
    parser.add_argument('-r', '--raw', action='store_true',
                        help="show raw XML without any processing")
    args = parser.parse_args(argv)

    filepath = os.path.abspath(args.file)
    xmlstring = XML_FILE.format(filepath=filepath.replace('"', '\\"'))
    xmlbytes = xmlstring.encode('utf-8')

    if args.raw:
        print(xmlstring)
    elif args.lxml:
        from lxml import etree
        if args.noxxe:
            parser = etree.XMLParser(resolve_entities=False)
            root = etree.XML(xmlbytes, parser)
        else:
            root = etree.XML(xmlbytes)
        print(etree.tostring(root).decode('utf-8'))
    else:
        printhandler = xml.sax.saxutils.XMLGenerator(encoding='utf-8')
        if args.noxxe:
            parser = xml.sax.make_parser()
            parser.setContentHandler(printhandler)
            parser.setFeature(xml.sax.handler.feature_external_ges, False)
            parser.parse(BytesIO(xmlbytes))
        else:
            xml.sax.parseString(xmlbytes, printhandler)
        print('')
    return 0


if __name__ == '__main__':
    sys.exit(main())
