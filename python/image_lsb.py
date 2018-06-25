#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2018 Nicolas Iooss
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
"""Extract the lowest significant bits from an image

Use Python Imaging Library (PIL) or its fork, Pillow, to open an image

@author: Nicolas Iooss
@license: MIT
"""
import argparse

from PIL import Image


class BitStream(object):
    """Push bits into a byte array"""
    def __init__(self, bit_size):
        self.bit_size = bit_size
        self.data = bytearray((bit_size + 7) // 8)
        self.idata_bits = 0
        self.cur_byte_value = 0

    def push_bit(self, bit):
        if bit:
            self.cur_byte_value |= 1 << (7 - (self.idata_bits & 7))
        self.idata_bits += 1
        if (self.idata_bits % 8) == 0:
            self.data[self.idata_bits // 8 - 1] = self.cur_byte_value
            self.cur_byte_value = 0

    def push_bits(self, bits, numbits):
        for ibit in range(numbits):
            self.push_bit((bits >> (numbits - 1 - ibit)) & 1)


def extract_lsb(im, bits, datamode):
    # Get the pixel values of the image
    pixels = im.getdata()
    new_pixels = [None] * len(pixels)
    bit_stream = BitStream(len(pixels) * 3 * bits)

    bitmask = (1 << bits) - 1
    color_mul = 255 // bitmask

    for ipixel, color in enumerate(pixels):
        r = (color[0] & bitmask) * color_mul
        g = (color[1] & bitmask) * color_mul
        b = (color[2] & bitmask) * color_mul
        new_pixels[ipixel] = (r, g, b)

        if datamode == 'RGB':
            pixel_data = (
                ((color[0] & bitmask) << (2 * bits)) |
                ((color[1] & bitmask) << (bits)) |
                (color[2] & bitmask))
        elif datamode == 'BGR':
            pixel_data = (
                ((color[2] & bitmask) << (2 * bits)) |
                ((color[1] & bitmask) << (bits)) |
                (color[0] & bitmask))
        else:
            raise RuntimeError("Unknown data mode %r" % datamode)

        bit_stream.push_bits(pixel_data, 3 * bits)

    im.putdata(new_pixels)
    return bit_stream.data


def main(argv=None):
    """Program entry point"""
    parser = argparse.ArgumentParser(
        description="Extract the lowest significant bits")
    parser.add_argument('image', nargs=1, type=str,
                        help="loaded image")
    parser.add_argument('-b', '--bits', type=int, default=1,
                        help="number of bits to take (1 by default)")
    parser.add_argument('-o', '--output', type=str,
                        help="save output image")
    parser.add_argument('-d', '--dataout', type=str,
                        help="save output binary data")
    parser.add_argument('-m', '--datamode', type=str, default='BGR',
                        help="specify the color mode of the data (RGB or BGR)")
    args = parser.parse_args(argv)

    im = Image.open(args.image[0])
    data = extract_lsb(im, args.bits, args.datamode)

    # Save the data if --dataout is used
    if args.dataout:
        with open(args.dataout, 'wb') as fout:
            fout.write(data)

    if args.output:
        im.save(args.output)
    else:
        im.show()


if __name__ == '__main__':
    main()
