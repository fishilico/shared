#!/usr/bin/env python3
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
"""Decode APDUs from pcscd logs

Usage:

  0. Kill the current PC/SC Daemon (pcscd)

    systemctl stop pcscd.service pcscd.socket

  1. As root user, start PC/SC Daemon (pcscd) with option --apdu in order to log
    the Application Protocol Data Unit packets (APDUs) in a temporary file:

    TERM=dumb /usr/bin/pcscd --foreground --auto-exit --apdu |tee /tmp/all_apdus.log

  2. As unprivileged user, pipe the output to this script:

    tail -F /tmp/all_apdus.log | ./decode_pcscdlog_apdus.py
"""
import argparse
import binascii
import sys
import re

from enum import IntEnum


COLOR_RED = '\033[31m'
COLOR_GREEN = '\033[32m'
COLOR_YELLOW = '\033[33m'
COLOR_NORM = '\033[m'


class INS(IntEnum):
    # ISO 7816-4 http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_6_basic_interindustry_commands.aspx
    ISO_ERASE_BINARY = 0x0e
    ISO_VERIFY = 0x20  # verify pin
    # 0x6X are invalid
    ISO_MANAGE_CHANNEL = 0x70
    ISO_EXTERNAL_AUTHENTICATE = 0x82
    ISO_GET_CHALLENGE = 0x84
    ISO_INTERNAL_AUTHENTICATE = 0x88
    # 0x9X are invalid
    ISO_SELECT_FILE = 0xa4
    ISO_READ_BINARY = 0xb0
    ISO_READ_RECORD = 0xb2
    ISO_GET_RESPONSE = 0xc0
    ISO_ENVELOPE = 0xc2
    ISO_GET_DATA = 0xca
    ISO_WRITE_BINARY = 0xd0
    ISO_WRITE_RECORD = 0xd2
    ISO_UPDATE_BINARY = 0xd6
    ISO_PUT_DATA = 0xda
    ISO_UPDATE_RECORD = 0xdc
    ISO_APPEND_RECORD = 0xe2

    # common
    CHANGE_REFERENCE_DATA = 0x24

    # OpenPGP applet
    OPGP_PERFORM_SECURITY_OPERATION = 0x2a
    OPGP_RESET_RETRY_COUNTER = 0x2c
    OPGP_ACTIVATE = 0x44
    OPGP_GENERATE_ASYMMETRIC_KEY_PAIR = 0x47
    OPGP_GET_DATA = ISO_GET_DATA
    OPGP_PUT_DATA = ISO_PUT_DATA
    OPGP_TERMINATE = 0xe6
    OPGP_GET_VERSION = 0xf1
    OPGP_SET_PIN_RETRIES = 0xf2

    # PIV instructions
    # https://opensource.apple.com/source/Tokend/Tokend-37563/PIV/PIVDefines.h
    PIV_GENERAL_AUTHENTICATE = 0x87
    PIV_GET_DATA = 0xcb


# Known applets from the YubiKey 4
KNOWN_APPLETS = {
    b'\xa0\x00\x00\x03\x08': "PIV",
    b'\xa0\x00\x00\x05\x27\x20\x01': "OTP",
    b'\xa0\x00\x00\x05\x27\x10\x02': "Old U2F",
    b'\xa0\x00\x00\x05\x27\x21\x01': "OATH",
    b'\xa0\x00\x00\x05\x27\x47\x11\x17': "MGR",  # Yubikey Manager
    b'\xa0\x00\x00\x06\x47\x2f\x00\x01': "U2F",
    b'\xd2\x76\x00\x01\x24\x01': "OpenPGP",  # D2 76 00 01 24 01 02 01 00 06 04 90 89 71 00 00
}


def bin2aid(binaid):
    """Convert an Application Identifier (AID) from binary to readable hexadecimal format"""
    aid = ''
    for i, x in enumerate(binaid):
        aid += '%02X' % x
        if i % 2:
            aid += ':'
    return aid.rstrip(':')


def analyze_line(line, show_pin=False):
    """Analyze a line form pcscd logs"""
    line = line.rstrip()

    # Filter PIN code if it was not asked to display it
    text_line = line
    if not show_pin:
        m = re.match(r'([0-9]* APDU: [0-9A-F]{2} 20 [0-9A-F]{2} (80|81|82))', line)
        if m:
            text_line = m.group(1) + ' ********'
    print("{}{}{}".format(COLOR_YELLOW, text_line, COLOR_NORM))

    # Match an APDU request from software to hardware
    m = re.match(r'[0-9]* APDU: ([0-9A-F ]+)$', line)
    if m is not None:
        apdu = binascii.unhexlify(m.group(1).replace(' ', ''))
        if len(apdu) < 4:
            return
        cl, ins, p1, p2 = apdu[:4]
        param = (p1 << 8) | p2

        try:
            oins = INS(ins)
        except ValueError:
            print("    Unknown instruction {:#x}".format(ins))
            return

        if cl == 0x10:  # Command chaining
            print(" => Command chaining {} (0x{:04x})[{}] {}".format(oins.name, param, len(apdu) - 4, repr(apdu[4:])))
            return
        if cl != 0:
            print("    Unknown class")
            return

        if oins == INS.ISO_SELECT_FILE and param == 0x400:
            length = apdu[4]
            if len(apdu) == 5 + length or (len(apdu) == 6 + length and apdu[-1] == 0):
                prefix = apdu[5:5 + length]
                selected_aids = sorted([aid for aid in KNOWN_APPLETS.keys() if aid[:length] == prefix[:len(aid)]])
                if selected_aids:
                    for aid in selected_aids:
                        print(" => SELECT Application {} ({} for {})".format(
                            KNOWN_APPLETS[aid], bin2aid(aid), bin2aid(prefix)))
                else:
                    print(" => SELECT unknown AID {}".format(bin2aid(prefix)))
                return
        elif oins == INS.ISO_VERIFY:
            if len(apdu) > 4:
                length = apdu[4]
                if len(apdu) == 5 + length and param in (0x81, 0x82):
                    print(" => OpenPGP VERIFY PIN {}: {}".format(
                        param - 0x80, repr(apdu[5:]) if show_pin else '********'))
                    return
                if len(apdu) == 5 + length and param == 0x80:
                    print(" => PIV VERIFY PIN {}: {}".format(
                        param - 0x80, repr(apdu[5:]) if show_pin else '********'))
                    return
            elif len(apdu) == 4 and param == 0x80:
                print(" => PIV VERIFY: is PIN {} ok?".format(param - 0x80))
                return
        elif oins == INS.OPGP_GET_DATA:
            if param == 0x4f:
                print(" => OpenPGP GET DATA: Application Identifier (D276:0001:2401:...)")
                return
            if param == 0x5e:
                print(" => OpenPGP GET DATA: Login data")
                return
            if param == 0x65:
                print(" => OpenPGP GET DATA: Cardholder Related Data (TLV, 5B=name, 5F2D=Language, 5F35=Sex)")
                return
            if param == 0x6e:
                print(" => OpenPGP GET DATA: Application Related Data (TLV)")
                return
            if param == 0x7a:
                print(" => OpenPGP GET DATA: Security support template (TLV, 93=Digital signature counter)")
                return
            if param == 0xc4:
                print(" => OpenPGP GET DATA: PW Status Bytes (pw1 status, {pw1, rc, pw3} max length, {pw1, rc, pw3} Pin tries)")  # noqa
                return
            if param == 0x0101:
                print(" => OpenPGP GET DATA: DO 0101")
                return
            if param == 0x0102:
                print(" => OpenPGP GET DATA: DO 0102")
                return
            if param == 0x5f50:
                print(" => OpenPGP GET DATA: URL")
                return
            if param == 0x5f52:
                print(" => OpenPGP GET DATA: Historical bytes")
                return
            if param == 0x7f21:
                print(" => OpenPGP GET DATA: Cardholder Certificate")
                return
        elif oins == INS.OPGP_GENERATE_ASYMMETRIC_KEY_PAIR and param == 0x8100 and len(apdu) > 4:
            length = apdu[4]
            if len(apdu) == 6 + length:
                print(" => OpenPGP Get public key 0x{}".format(binascii.hexlify(apdu[5:5 + length]).decode('ascii')))
                return
        elif oins == INS.OPGP_PERFORM_SECURITY_OPERATION:
            if param == 0x8086:
                print(" => OpenPGP Decipher (...)")
                return
            if param == 0x9E9A:
                print(" => OpenPGP Compute Digital Signature (...)")
                return
        elif oins == INS.PIV_GET_DATA and param == 0x3fff:
            length = apdu[4]
            if len(apdu) == 6 + length:
                data_mark = apdu[5:5 + length]
                # https://github.com/aosm/Tokend/blob/master/PIV/PIVDefines.h
                # OpenSC: card-piv.c
                desc = 'TLV {}'.format(binascii.hexlify(data_mark))
                if data_mark == b'\x5c\x03\x5f\xc1\x01':
                    desc = 'X.509 Certificate for Card Authentication (2.16.840.1.101.3.7.2.5.0)'
                elif data_mark == b'\x5c\x03\x5f\xc1\x02':
                    desc = 'Card Holder Unique Identifier (2.16.840.1.101.3.7.2.48.0)'
                elif data_mark == b'\x5c\x03\x5f\xc1\x03':
                    desc = 'Card Holder Fingerprints (2.16.840.1.101.3.7.2.96.16)'
                elif data_mark == b'\x5c\x03\x5f\xc1\x05':
                    desc = 'X.509 Certificate for PIV Authentication (2.16.840.1.101.3.7.2.1.1)'
                elif data_mark == b'\x5c\x03\x5f\xc1\x06':
                    desc = 'Security Object (2.16.840.1.101.3.7.2.144.0)'
                elif data_mark == b'\x5c\x03\x5f\xc1\x07':
                    desc = 'Card Capability Container (2.16.840.1.101.3.7.1.219.0)'
                elif data_mark == b'\x5c\x03\x5f\xc1\x08':
                    desc = 'Cardholder Facial Images (2.16.840.1.101.3.7.2.96.48)'
                elif data_mark == b'\x5c\x03\x5f\xc1\x09':
                    desc = 'Printed Information (2.16.840.1.101.3.7.2.48.1)'
                elif data_mark == b'\x5c\x03\x5f\xc1\x0a':
                    desc = 'X.509 Certificate for Digital Signature (2.16.840.1.101.3.7.2.1.0)'
                elif data_mark == b'\x5c\x03\x5f\xc1\x0b':
                    desc = 'X.509 Certificate for Key Management (2.16.840.1.101.3.7.2.1.2)'
                elif data_mark == b'\x5c\x03\x5f\xc1\x0c':
                    desc = 'Key History Object (2.16.840.1.101.3.7.2.96.96)'
                elif data_mark == b'\x5c\x03\x5f\xc1\x21':
                    desc = 'Cardholder Iris Images (2.16.840.1.101.3.7.2.16.21)'
                elif data_mark == b'\x5c\x01\x7e':
                    desc = 'Discovery Object (2.16.840.1.101.3.7.2.96.80)'
                print(" => PIV GET DATA (retsize {}) {}".format(apdu[-1], desc))
                return
        elif oins == INS.PIV_GENERAL_AUTHENTICATE and p1 == 0:
            length = apdu[4]
            # magic value from https://github.com/OpenSC/OpenSC/blob/645780e6d4c4e70fbd75eec0c5cd2c3a7bd81879/src/libopensc/card-piv.c#L1894  # noqa
            if len(apdu) == 6 + length and apdu[5:5 + length] == b'\x7c\x02\x81\x00':
                # reqdata = apdu[5:5 + length]
                print(" => PIV Get challenge (keyref {:#x})".format(p2))
                # Response: 7C 0A 81 08 79 B5 E9 B1 57 F9 81 89
                # =>
                #   7C          Tag "Dynamic Authentication Template"
                #   0A          Length (10 bytes)
                #   81 08       Challenge, 8 bytes
                #   79 B5 E9 B1 57 F9 81 89 : challenge
                return
        elif oins == INS.PIV_GENERAL_AUTHENTICATE and p1 == 0x07:
            length = apdu[4]
            if len(apdu) == 6 + length:
                print(" => PIV GENERAL AUTHENTICATE RSA 2048 (keyref {:#x}) (challenge...)".format(p2))
                return
        print(" => {} ({:#x}, {:#x} = {:#x}) {}".format(oins.name, p1, p2, param, repr(apdu[4:])))

    # Match an Status Word response from hardware to software
    m = re.match(r'[0-9]* SW: ([0-9A-F ]+)$', line)
    if m is not None:
        swdata = binascii.unhexlify(m.group(1).replace(' ', ''))
        if len(swdata) < 2:
            return
        sw1, sw2 = swdata[-2:]
        sw = (sw1 << 8) | sw2
        swdata = swdata[:-2]
        if sw == 0x9000:
            if swdata:
                print("{} <= OK: {}{}".format(COLOR_GREEN, repr(swdata), COLOR_NORM))
            else:
                print("{} <= OK{}".format(COLOR_GREEN, COLOR_NORM))
        elif sw1 == 0x61:
            print("{} <= SW Bytes remaining {}: {}{}".format(COLOR_GREEN, sw2, repr(swdata), COLOR_NORM))
        elif (sw & 0xfff0) == 0x63c0 and not swdata:
            print(" <= SW: PIN remaining tries: {}".format(sw & 0xf))
        elif sw == 0x6700 and not swdata:
            print("{} <= SW: Wrong length{}".format(COLOR_RED, COLOR_NORM))
        elif sw == 0x6982 and not swdata:
            print("{} <= SW: Security condition not satisfied{}".format(COLOR_RED, COLOR_NORM))
        elif sw == 0x6a81 and not swdata:
            print("{} <= SW: Function not supported{}".format(COLOR_RED, COLOR_NORM))
        elif sw == 0x6a82 and not swdata:
            print("{} <= SW: File not found{}".format(COLOR_RED, COLOR_NORM))
        elif sw == 0x6b00 and not swdata:
            print("{} <= SW: Wrong parameters P1-P2{}".format(COLOR_RED, COLOR_NORM))
        elif sw == 0x6d00 and not swdata:
            print("{} <= SW: Instruction not supported or invalid{}".format(COLOR_RED, COLOR_NORM))
        elif sw == 0x6e00 and not swdata:
            print("{} <= SW: Class not supported{}".format(COLOR_RED, COLOR_NORM))
        else:
            print("{} <= SW {:04x}: {}{}".format(COLOR_RED, sw, repr(swdata), COLOR_NORM))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Decode APDUs from pcscd logs")
    parser.add_argument('-P', '--show-pin', action='store_true',
                        help="Show the user PIN (it is hidden by default)")
    args = parser.parse_args(argv)

    for line in sys.stdin:
        analyze_line(line, show_pin=args.show_pin)


if __name__ == '__main__':
    main()
