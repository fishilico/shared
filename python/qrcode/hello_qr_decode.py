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
"""Decode a basic QR code containing a Hello world message

Documentation:
* http://blog.qartis.com/decoding-small-qr-codes-by-hand/
  https://web.archive.org/web/20181024141957/http://blog.qartis.com/decoding-small-qr-codes-by-hand/
"""
import os.path
from PIL import Image, ImageDraw


# Polynom X10 + X8 + X5 + X4 + X2 + X + 1
QR_BCH_POLYNOM = (1 << 10) + (1 << 8) + (1 << 5) + 16 + 4 + 2 + 1  # 0x537


def zbar_bch15_5_encode(x):
    """ZBar's implementation of bch15_5_encode"""
    return (
        (-(x & 1) & 0x0537) ^
        (-(x >> 1 & 1) & 0x0A6E) ^
        (-(x >> 2 & 1) & 0x11EB) ^
        (-(x >> 3 & 1) & 0x23D6) ^
        (-(x >> 4 & 1) & 0x429B)
    )


def qrformat_bch(value):
    """Compute the 15-bit format corresponding to the 5-bit value"""
    assert 0 <= value < 32
    bch = value << 10
    for i in range(5):
        if bch & (1 << (14 - i)):
            bch ^= QR_BCH_POLYNOM << (4 - i)
    return bch ^ (value << 10)


def qrformat_bch_check(value):
    """Check the parity of the value"""
    for i in range(5, -1, -1):
        if value & (1 << (10 + i)):
            value ^= QR_BCH_POLYNOM << i
    return value == 0


def decode_qr_grid(qrgrid):
    """Decode a QR code grid"""
    qrsize = len(qrgrid)
    assert all(len(col) == qrsize for col in qrgrid), "not a square grid"

    # Extract format info, which is present in lines
    format_int1 = 0
    format_int2 = 0
    for y in range(6):
        format_int1 |= qrgrid[8][y] << y
    format_int1 |= qrgrid[8][7] << 6
    format_int1 |= qrgrid[8][8] << 7
    format_int1 |= qrgrid[7][8] << 8
    for x in range(6):
        format_int1 |= qrgrid[5 - x][8] << (x + 9)

    for x in range(8):
        format_int2 |= qrgrid[qrsize - 1 - x][8] << x
    assert qrgrid[8][qrsize - 8] == 1  # "unused" bit
    for y in range(7):
        format_int2 |= qrgrid[8][qrsize - 7 + y] << (8 + y)

    # cf. http://upload.wikimedia.org/wikipedia/commons/4/49/QRCode-4-Levels%2CMasks.png for the magic masking
    fmtint1 = format_int1 ^ int('101010000010010', 2)
    fmtint2 = format_int2 ^ int('101010000010010', 2)

    if qrformat_bch_check(fmtint1):
        fmtint = fmtint1
        if qrformat_bch_check(fmtint2):
            if fmtint1 != fmtint2:
                print("Error: format-1 ({:#x}) and format-2 ({:#x}) were sane but different".format(fmtint1, fmtint2))
                raise ValueError("Disagreeing format integers")
        else:
            print("Warning: format-1 ({:#x}) was corrupted, using format-2 ({:#x})".format(fmtint1, fmtint2))
    else:
        if qrformat_bch_check(fmtint2):
            print("Warning: format-2 ({:#x}) was corrupted, using format-1 ({:#x})".format(fmtint2, fmtint1))
            fmtint = fmtint2
        else:
            print("Error: format-1 ({:#x}) and format-2 ({:#x}) were corrupted".format(fmtint1, fmtint2))
            raise ValueError("Unable to decode format")

    # Sanity checks
    assert qrformat_bch_check(fmtint)
    assert qrformat_bch(fmtint >> 10) == fmtint
    assert zbar_bch15_5_encode(fmtint >> 10) == fmtint

    edc_level = fmtint >> 13
    mask = (fmtint >> 10) & 7
    print("QR code size={}, format={:#x}: EDC level {} Mask {}".format(qrsize, fmtint, edc_level, mask))

    # Apply the mask
    for x in range(qrsize):
        for y in range(qrsize):
            if (x <= 8 and y <= 8) or (x <= 8 and y >= qrsize - 8) or (x >= qrsize - 8 and y <= 8):
                continue
            if mask == 4:
                if (y // 2 + x // 3) % 2 == 0:
                    qrgrid[x][y] ^= 1
            elif mask == 6:
                if ((x * y) % 3 + x * y) % 2 == 0:
                    qrgrid[x][y] ^= 1
            else:
                raise NotImplementedError("Unknown QR code mask {}".format(mask))

    if qrsize == 21:
        # Decode the encoding
        encoding = qrgrid[20][20] << 3
        encoding |= qrgrid[19][20] << 2
        encoding |= qrgrid[20][19] << 1
        encoding |= qrgrid[19][19]

        if encoding == 4:
            print("... encoding {}: Bytes".format(encoding))
        else:
            print("... encoding {}: ?".format(encoding))

        blocks = bytearray(19)
        # Positions to turn up2down
        turn_pos = [(3, 1), (2, 1), (3, 0), (2, 0), (1, 0), (0, 0), (1, 1), (0, 1)]
        for i in range(4):
            for j in range(2):
                tposx, tposy = turn_pos[i * 2 + j]
                blocks[0] |= qrgrid[20 - j][18 - i] << (7 - (i * 2 + j))
                blocks[1] |= qrgrid[20 - j][14 - i] << (7 - (i * 2 + j))
                blocks[2] |= qrgrid[17 + tposx][9 + tposy] << (7 - (i * 2 + j))
                blocks[3] |= qrgrid[18 - j][11 + i] << (7 - (i * 2 + j))
                blocks[4] |= qrgrid[18 - j][15 + i] << (7 - (i * 2 + j))
                blocks[5] |= qrgrid[15 + tposx][20 - tposy] << (7 - (i * 2 + j))
                blocks[6] |= qrgrid[16 - j][18 - i] << (7 - (i * 2 + j))
                blocks[7] |= qrgrid[16 - j][14 - i] << (7 - (i * 2 + j))
                blocks[8] |= qrgrid[13 + tposx][9 + tposy] << (7 - (i * 2 + j))
                blocks[9] |= qrgrid[14 - j][11 + i] << (7 - (i * 2 + j))
                blocks[10] |= qrgrid[14 - j][15 + i] << (7 - (i * 2 + j))
                blocks[11] |= qrgrid[11 + tposx][20 - tposy] << (7 - (i * 2 + j))
                blocks[12] |= qrgrid[12 - j][18 - i] << (7 - (i * 2 + j))
                blocks[13] |= qrgrid[12 - j][14 - i] << (7 - (i * 2 + j))
                blocks[14] |= qrgrid[12 - j][10 - i] << (7 - (i * 2 + j))
                blocks[15] |= qrgrid[12 - j][5 - i] << (7 - (i * 2 + j))
                blocks[16] |= qrgrid[9 + tposx][0 + tposy] << (7 - (i * 2 + j))
                blocks[17] |= qrgrid[10 - j][2 + i] << (7 - (i * 2 + j))
                blocks[18] |= qrgrid[10 - j][7 + i] << (7 - (i * 2 + j))

        print("... hex: {}".format(' '.join('{:02x}'.format(b) for b in blocks)))
        if encoding == 4:
            # Byte encoding
            length = blocks[0]
            if length >= len(blocks):
                print("Error: length {} too large".format(length))
            else:
                print("... bytes[{}]: {}".format(blocks[0], repr(bytes(blocks[1:length + 1]))))
                if length + 1 < len(blocks):
                    print("... padding: {}".format(repr(bytes(blocks[length + 1:]))))


def draw_grid(qrgrid):
    """Draw a QR code grid"""
    qrsize = len(qrgrid)
    assert all(len(col) == qrsize for col in qrgrid), "not a square grid"

    im = Image.new("RGB", (qrsize * 8, qrsize * 8), "blue")
    draw = ImageDraw.Draw(im)
    for (x, column) in enumerate(qrgrid):
        for (y, val) in enumerate(column):
            if (x <= 8 and y <= 8) or (x <= 8 and y >= qrsize - 8) or (x >= qrsize - 8 and y <= 8) or (x == 6 or y == 6):  # noqa
                # Grayify the timing patterns and the format lines
                draw.rectangle((x * 8, y * 8, (x+1) * 8, (y+1) * 8), "darkgray" if val else "lightgray")
            elif val == 1:
                draw.rectangle((x * 8, y * 8, (x+1) * 8, (y+1) * 8), "black")
            elif val == 0:
                draw.rectangle((x * 8, y * 8, (x+1) * 8, (y+1) * 8), "white")
    return im


def decode_hello():
    """Decode a basic QR code"""
    # Load the image
    im = Image.open(os.path.join(os.path.dirname(__file__), 'barcode-image21helloqrworld.png'))
    im = im.crop((24, 24, 108, 108))
    imdata = im.getdata()

    qrsize = 21
    qrgrid = [[None] * qrsize for _ in range(qrsize)]
    for x in range(qrsize):
        for y in range(qrsize):
            qrgrid[x][y] = 0 if imdata[(4 * y + 2) * 84 + (4 * x + 2)][0] & 0x80 else 1
    del imdata
    del im

    decode_qr_grid(qrgrid)

    # Show the grid
    # im = draw_grid(qrgrid)
    # im.show()


if __name__ == '__main__':
    decode_hello()
