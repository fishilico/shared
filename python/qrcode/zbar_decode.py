#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2019 Nicolas Iooss
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
"""Decode QR codes (Quick Response codes) with ZBar Bar Code Reader Library

http://zbar.sourceforge.net/

There are several Python bindings with zbar:

* The official one is Python2-only
* pyzbar (https://pypi.org/project/pyzbar/) is compatible with Python 3

QR codes can contain WiFi passwords, in which case the data looks like this:

    WIFI:S:wifiAPName;T:WPA;P:wifiPassword;;

@author: Nicolas Iooss
@license: MIT
"""
import argparse
from PIL import Image, ImageDraw

from pyzbar import pyzbar


def copy_image_on_black(image):
    """Replace transparent pixels to black"""
    new_image = Image.new('RGB', image.size, (0, 0, 0))
    new_image.paste(image, mask=image)  # The alpha channel is used as mask
    return new_image


def copy_image_on_white(image):
    """Replace transparent pixels to white"""
    new_image = Image.new('RGB', image.size, (255, 255, 255))
    new_image.paste(image, mask=image)  # The alpha channel is used as mask
    return new_image


def main(argv=None):
    parser = argparse.ArgumentParser(description="Decode QR codes")
    parser.add_argument('images', metavar='IMAGE', nargs='+',
                        help="images to scan")
    parser.add_argument('-b', '--bgblack', action='store_true',
                        help="Use black background for transparent images")
    parser.add_argument('-w', '--bgwhite', action='store_true',
                        help="Use white background for transparent images")
    parser.add_argument('-s', '--show', action='store_true',
                        help="Show the found QRcode in the image")
    args = parser.parse_args(argv)

    if args.bgblack and args.bgwhite:
        parser.error("Options --bgblack and --bgwhite are mutualy exclusive")

    for image_path in args.images:
        image = Image.open(image_path).convert('RGBA')
        if args.bgblack:
            image = copy_image_on_black(image)
        elif args.bgwhite:
            image = copy_image_on_white(image)

        for symbol in pyzbar.decode(image):
            print("Symbol at {}:".format(symbol.rect))
            print("  {}: {}".format(symbol.type, repr(symbol.data)))

            if args.show:
                modified_image = image.copy()
                draw = ImageDraw.Draw(modified_image)
                sym_x = symbol.rect.left
                sym_y = symbol.rect.top
                draw.rectangle(
                    (
                        (sym_x, sym_y),
                        (sym_x + symbol.rect.width, sym_y + symbol.rect.height)
                    ),
                    outline='#0000ff'
                )
                draw.polygon(symbol.polygon, outline='#0088ff')
                modified_image.show()


if __name__ == '__main__':
    main()
