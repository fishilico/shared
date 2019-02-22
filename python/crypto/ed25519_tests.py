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
"""Perform some operations with Ed25519 algorithm

Curve25519:
* q = 2**255 - 19
    = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
* d = (-121665 / 121666) modulo q
    = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
* i = sqrt(-1) modulo q
    = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0
* Base point (generator):
  * B.x = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
  * B.y = 4/5
        = 0x6666666666666666666666666666666666666666666666666666666666666658
  * order l = 2**252 + 27742317777372353535851937790883648493
            = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
  * (l * B) = {x=0, y=1}

Twisted Edwards curve: -x**2 + y**2 = 1 + d x**2 y**2
Montgomery curve expression: y**2 = x**3 + 486662 x**2 + x, base point (x = 9)

Equivalence equations from Montgomery curve (u, v) to Twisted Edwards curve (x, y):
* x = u/v * sqrt(-486664)
* y = (u - 1) / (u + 1)

Inverse equation:
* u = (1 + y) / (1 - y)
* v = u/x * sqrt(-486664)

Documentation:
* https://en.wikipedia.org/wiki/EdDSA
  Ed25519 is the EdDSA signature scheme using SHA-512/256 and Curve25519
* https://en.wikipedia.org/wiki/Curve25519
* https://ed25519.cr.yp.to/
* https://ed25519.cr.yp.to/python/ed25519.py
* https://linux-audit.com/using-ed25519-openssh-keys-instead-of-dsa-rsa-ecdsa/
  Using Ed25519 for OpenSSH keys (instead of DSA/RSA/ECDSA)
"""
import argparse
import base64
import binascii
import errno
import hashlib
import logging
import os
import struct
import subprocess
import sys
import tempfile


logger = logging.getLogger(__name__)


COLOR_RED = '\033[31m'
COLOR_GREEN = '\033[32m'
COLOR_PURPLE = '\033[35m'
COLOR_NORM = '\033[m'


ED25519_PRIME = 2**255 - 19


def run_process_with_input(cmdline, data, color=None):
    """Run the given command with the given data and show its output in colors"""
    print("Output of \"{}\":".format(' '.join(cmdline)))
    if color:
        sys.stdout.write(color)
    sys.stdout.flush()
    proc = subprocess.Popen(cmdline, stdin=subprocess.PIPE)
    proc.stdin.write(data)
    proc.stdin.close()
    ret = proc.wait()
    if color:
        sys.stdout.write(COLOR_NORM)
        sys.stdout.flush()
    if ret != 0:
        logger.error("command %s returned %d", ' '.join(cmdline), ret)
        return False
    return True


def hexdump(data, color=''):
    """Show an hexdecimal dump of binary data"""
    if color:
        sys.stdout.write(color)
    for iline in range(0, len(data), 16):
        hexline = ''
        ascline = ''
        for i in range(16):
            if iline + i >= len(data):
                hexline += '  '
            else:
                # pylint: disable=invalid-name
                x = data[iline + i] if sys.version_info >= (3,) else ord(data[iline + i])
                hexline += '{:02x}'.format(x)
                ascline += chr(x) if 32 <= x < 127 else '.'
            if i % 2:
                hexline += ' '
        print(" {:06x}:  {} {}".format(iline, hexline, ascline))
    if color:
        sys.stdout.write(COLOR_NORM)


def xx(data):
    """One-line hexadecimal representation of binary data"""
    return binascii.hexlify(data).decode('ascii')


def decode_bigint_le(data):
    """Decode a Little-Endian big integer"""
    if sys.version_info < (3,):
        return sum(ord(x) << (8 * i) for i, x in enumerate(data))
    return sum(x << (8 * i) for i, x in enumerate(data))


def encode_bigint_le(value, bytelen=None):
    """Encode a Little-Endian big integer"""
    if bytelen is None:
        bytelen = (value.bit_length() + 7) // 8
    data = bytearray(bytelen)
    for i in range(bytelen):
        data[i] = value & 0xff
        value >>= 8
    assert value == 0
    return bytes(data)


# pylint: disable=invalid-name
def extended_gcd(aa, bb):
    """Extended greatest common divisor

    from https://rosettacode.org/wiki/Modular_inverse#Python
    """
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)


def modinv(a, m):
    """Modular inverse

    from https://rosettacode.org/wiki/Modular_inverse#Python
    """
    # pylint: disable=invalid-name,unused-variable
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m


def modsqrt25519(x2):
    """Modular square root, modulus 2**255 - 19

    As q % 8 = 5, the square root of x can be x^((q+3)/8) or i*x^((q+3)/8)
    """
    x = pow(x2, (ED25519_PRIME + 3) // 8, ED25519_PRIME)
    if (x * x - x2) % ED25519_PRIME != 0:
        x = (x * Ed25519.i) % ED25519_PRIME
        assert (x * x - x2) % ED25519_PRIME == 0
    # Choose the even value
    if x % 2:
        return ED25519_PRIME - x
    return x


class Ed25519Point(object):
    """Point on Ed25519 curve"""
    def __init__(self, x, y):
        assert Ed25519.has_point(x, y)
        self.x = x
        self.y = y

    def __str__(self):
        return '({:#x},{:#x})'.format(self.x, self.y)

    def __repr__(self):
        return '{}({:#x},{:#x})'.format(self.__class__.__name__, self.x, self.y)

    @classmethod
    def from_y(cls, y):
        """Compute x from y

        x^2 = (y^2 - 1) / (dy^2 + 1)
        x = sqrt(x^2) in F_q
        """
        x = modsqrt25519((y * y - 1) * modinv(Ed25519.d * y * y + 1, Ed25519.q))
        return cls(x, y)

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __add__(self, other):
        """Add two points together, on the twisted Edwards curve"""
        q = ED25519_PRIME
        x1 = self.x
        y1 = self.y
        x2 = other.x
        y2 = other.y
        dx1x2y1y2 = (Ed25519.d * x1 * x2 * y1 * y2) % q
        x3 = ((x1 * y2 + y1 * x2) % q) * modinv(1 + dx1x2y1y2, q)
        y3 = ((y1 * y2 + x1 * x2) % q) * modinv(1 - dx1x2y1y2, q)
        return Ed25519Point(x3 % q, y3 % q)

    def __mul__(self, other):
        """Multiply a point by an integer (exponentiation)"""
        e = other
        if e == 0:
            return Ed25519Point(0, 1)
        if e == 1:
            return Ed25519Point(self.x, self.y)
        result = self
        bitmask = 1 << (e.bit_length() - 2)
        while bitmask >= 1:
            # square
            result = result + result
            if e & bitmask:
                result += self
            bitmask = bitmask // 2
        return result

    def encode(self):
        """Encode a point in a compressed binary form"""
        bits = Ed25519.bits
        if self.x & 1:
            y = self.y | 1 << (bits - 1)
        else:
            y = self.y & ~(1 << (bits - 1))
        return encode_bigint_le(y, Ed25519.bits // 8)

    @classmethod
    def decode(cls, compressed):
        """Decode a point in a compressed binary form"""
        y = decode_bigint_le(compressed)
        bits = Ed25519.bits
        parity = y >> (bits - 1)
        assert parity in (0, 1)
        pt = cls.from_y(y & ~(1 << (bits - 1)))
        if pt.x & 1 != parity:
            assert pt.x != 0
            pt.x = ED25519_PRIME - pt.x
        return pt

    def to_montgomery(self):
        """Get the equivalent point on the Montgomery curve for Ed25519

        u = (1 + y) / (1 - y)
        v = u/x * sqrt(-486664)
        """
        if self.y == 1:
            # (0, 1) is mapped to the infinity point
            assert self.x == 0
            return Montgomery25519Point(None, None)
        q = ED25519_PRIME
        u = ((1 + self.y) * modinv(1 - self.y, q)) % q
        v = (u * modinv(self.x, q) * modsqrt25519(-486664)) % q
        return Montgomery25519Point(u, v)


class Montgomery25519Point(object):
    """Point on Montgomery curve for Ed25519"""
    def __init__(self, x, y):
        if x is not None or y is not None:
            y2 = (y * y) % ED25519_PRIME
            x2 = (x * x) % ED25519_PRIME
            x3 = (x2 * x) % ED25519_PRIME
            assert y2 == (x3 + 486662 * x2 + x) % ED25519_PRIME
        self.x = x
        self.y = y

    def __str__(self):
        if self.x is None:
            return 'INFINITY'
        return '({:#x},{:#x})'.format(self.x, self.y)

    def __repr__(self):
        if self.x is None:
            return '{}.INFINITY'.format(self.__class__.__name__)
        return '{}({:#x},{:#x})'.format(self.__class__.__name__, self.x, self.y)

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def mul_2(self):
        """Compute the double of the point on curve y^2 = x^3 + 486662*x^2 + x mod q
        i.e. b*y^2 = x^3 + a*x^2 + x mod q with b = 1 and a = 486662

        The tangent at (x, y) has a slope l := dy/dx = (3x^2 + 2a*x + 1) / (2b*y)
        So its equation for (X, Y) is Y = y + l * (X - x)
        Its intersection with the curve is:

            b*Y^2 = X^3 + a*X^2 + X
            b*y^2 + 2*b*y*l*(X - x) + b*l^2*(X - x)^2 = X^3 + a*X^2 + X
            (x^3 + a*x^2 + x) + (3*x^2 + 2*a*x + 1)*(X - x) + b*l^2*(X - x)^2 = X^3 + a*X^2 + X
            (3*x^2 + 2*a*x + 1)*(X - x) + b*l^2*(X - x)^2 = (X - x)*(X^2 + x*X + x^2 + a*X + a*x + 1)
        With X != x:
            3*x^2 + 2*a*x + 1 + b*l^2*(X - x) = X^2 + x*X + x^2 + a*X + a*x + 1
            b*l^2*(X - x) = (X^2 + x*X - 2*x^2) + a*(X - x)
            b*l^2*(X - x) = (X - x)*(X + 2*x) + a*(X - x)
        With X != x:
            b*l^2 = X + 2*x + a
            X = b*l^2 - 2*x - a
        """
        if self.x is None:
            return Montgomery25519Point(None, None)
        q = ED25519_PRIME
        slope = ((3 * self.x * self.x + 2 * 486662 * self.x + 1) * modinv(2 * self.y, q)) % q
        x3 = (slope * slope - 2 * self.x - 486662) % q
        y3 = (slope * (self.x - x3) - self.y) % q
        return Montgomery25519Point(x3, y3)

    def __add__(self, other):
        """Add two points together

        Curve: y^2 = x^3 + 486662*x^2 + x mod q
        b*y^2 = x^3 + a*x^2 + x mod q with b = 1 and a = 486662

        With S=self and O=other and I(X,Y)=intersection, S + O = -I:
        * b*sy^2 = sx^3 + a*sx^2 + sx mod q
        * b*oy^2 = ox^3 + a*ox^2 + ox mod q
        * b*Y^2 = X^3 + a*X^2 + X mod q

        define l := (oy - sy) / (ox - sx)
        the line joining S, O and I is defined by: Y = sy + l * (X - sx)

        Intersection:
            b*Y^2 = X^3 + a*X^2 + X
            b*(sy + l*(X - sx))^2 = X^3 + a*X^2 + X
            b*(sy^2 + 2*sy*l*(X - sx) + l^2*(X - sx)^2) = X^3 + a*X^2 + X
            2*b*sy*l*(X - sx) + b*l^2*(X - sx)^2 = X^3 + a*X^2 + X - (b*sy^2)
            2*b*sy*l*(X - sx) + b*l^2*(X - sx)^2 = X^3 + a*X^2 + X - (sx^3 + a*sx^2 + sx)
            2*b*sy*l*(X - sx) + b*l^2*(X - sx)^2 = (X - sx)(X^2 + sx*X + sx^2) + a*(X - sx)*(X + sx) + (X - sx)
        With X != sx:
            2*b*sy*l + b*l^2*(X - sx) = X^2 + sx*X + sx^2 + a*(X + sx) + 1
            2*b*sy*l + b*l^2*(X - ox + ox - sx) = ...
            2*b*sy*l + b*l^2*(X - ox) + b*l*(oy - sy) = ...
            b*l*(oy + sy) + b*l^2*(X - ox) = X^2 + sx*X + sx^2 + a*(X + sx) + 1
        Stufying a term:
            b*l*(oy + sy) = b*(oy - sy)*(oy + sy)/(ox - sx)
                = (b*oy^2 - b*sy^2)/(ox - sx)
                = (ox^3 + a*ox^2 + ox - (sx^3 + a*sx^2 + sx))/(ox - sx)
                = ox^2 + ox*sx + sx^2 + a*(ox + sx) + 1
        Therefore:
            ox^2 + ox*sx + sx^2 + a*(ox + sx) + b*l^2*(X - ox) = X^2 + sx*X + sx^2 + a*(X + sx)
            b*l^2*(X - ox) = (X - ox)(X + ox + sx + a)
        With X != ox:
            b*l^2 = X + ox + sx + a
            X = b*l^2 - ox - sx - a
        The base equation is:
            sx + ox + X = b*l^2 - a
        """
        if self.x is None:
            # INFINITY + other = other
            return Montgomery25519Point(other.x, other.y)
        if other.x is None:
            # self + INFINITY = self
            return Montgomery25519Point(self.x, self.y)

        q = ED25519_PRIME

        if self.x == other.x:
            if (self.y + other.y) % q == 0:
                # self and other are opposite
                return Montgomery25519Point(None, None)
            assert self.y == other.y
            return self.mul_2()

        slope = ((other.y - self.y) * modinv(other.x - self.x, q)) % q
        x3 = (slope * slope - self.x - other.x - 486662) % q
        y3 = (slope * (self.x - x3) - self.y) % q
        return Montgomery25519Point(x3, y3)

    def __mul__(self, other):
        """Multiply a point by an integer (exponentiation)"""
        e = other
        if e == 0:
            return Montgomery25519Point(None, None)
        if e == 1:
            return Montgomery25519Point(self.x, self.y)
        result = self
        bitmask = 1 << (e.bit_length() - 2)
        while bitmask >= 1:
            # square
            result = result + result
            if e & bitmask:
                result += self
            bitmask = bitmask // 2
        return result

    def to_edwards(self):
        """Get the equivalent point on Twisted Edwards curve Ed25519

        x = u/v * sqrt(-486664)
        y = (u - 1) / (u + 1)
        """
        if self.x is None:
            return Ed25519Point(0, 1)
        q = ED25519_PRIME
        x = (self.x * modinv(self.y, q) * modsqrt25519(-486664)) % q
        y = ((self.x - 1) * modinv(self.x + 1, q)) % q
        return Ed25519Point(x, y)


class Ed25519(object):
    """Ed25519 curve"""
    bits = 256  # size of messages, in bits
    q = ED25519_PRIME  # prime number
    i = pow(2, (q - 1) // 4, q)  # sqrt(-1) in F_q

    # twisted Edwards curve -x^2 + y^2 = 1 + dx^2y^2
    d = (-121665 * modinv(121666, q)) % q

    def __init__(self):
        # base point
        self.b = Ed25519Point.from_y((4 * modinv(5, self.q)) % self.q)
        assert (5 * self.b.y) % self.q == 4

        # order of B
        self.ordb = 2**252 + 27742317777372353535851937790883648493
        pt = self.b * self.ordb
        assert pt.x == 0 and pt.y == 1

    @classmethod
    def has_point(cls, x, y):
        """Check whether (x, y) belongs to the curve"""
        assert 0 <= x < cls.q
        assert 0 <= y < cls.q
        return (- x * x + y * y - 1 - cls.d * x * x * y * y) % cls.q == 0

    @staticmethod
    def hash(message):
        """Used hash function, SHA-512"""
        return hashlib.sha512(message).digest()

    @classmethod
    def hash_int(cls, message):
        """Used hash function with conversion to an integer"""
        return decode_bigint_le(cls.hash(message)[:cls.bits // 4])

    def private_key(self, secret):
        """Get the private key associated with the secret"""
        bits = self.bits
        privkey = decode_bigint_le(self.hash(secret)[:bits // 8])
        return (privkey | (1 << (bits - 2))) & ~(7 | (1 << (bits - 1)))

    def public_key(self, secret):
        """Get the public key associated with the secret"""
        pubkey = self.b * self.private_key(secret)
        return pubkey.encode()

    def sign(self, message, secret, public_key=None):
        """Sign a message with Ed25519 and the secret"""
        privkey = self.private_key(secret)
        if public_key is None:
            public_key = self.public_key(secret)

        bits = self.bits
        ordb = self.ordb
        h = self.hash(secret)
        r = self.hash_int(h[bits // 8:bits // 4] + message)
        r_point = (self.b * r).encode()
        hash_for_s = self.hash_int(r_point + public_key + message) % ordb
        s = (r + privkey * hash_for_s) % ordb
        return r_point + encode_bigint_le(s, bits // 8)

    def check_signature(self, message, signature, public_key):
        """Check a signed message with the public key"""
        bits = self.bits
        if len(signature) != bits // 4:
            raise ValueError("wrong signature length")
        if len(public_key) != bits // 8:
            raise ValueError("wrong public key length")
        r_point = Ed25519Point.decode(signature[:bits // 8])
        pk_point = Ed25519Point.decode(public_key)
        h = self.hash_int(signature[:bits // 8] + public_key + message)
        test_point = r_point + (pk_point * h)

        s = decode_bigint_le(signature[bits // 8:])
        bs_point = self.b * s
        if test_point.x != bs_point.x or test_point.y != bs_point.y:
            raise ValueError("invalid signature")


# Ensure that i^2 = -1 in F_q
assert (Ed25519.i * Ed25519.i) % Ed25519.q == Ed25519.q - 1


def run_test(colorize):
    """Test operations on Ed25519"""
    color_red = COLOR_RED if colorize else ''
    color_green = COLOR_GREEN if colorize else ''
    color_norm = COLOR_NORM if colorize else ''

    curve = Ed25519()

    print("Ed25519 curve:")
    print("* bits: {}".format(curve.bits))
    print("* q({}): {:#x}".format(curve.q.bit_length(), curve.q))
    print("* d({}): {:#x}".format(curve.d.bit_length(), curve.d))
    print("* i({}): {:#x}".format(curve.i.bit_length(), curve.i))
    print("* B: {}".format(curve.b))
    print("* order of B, l({}): {:#x}".format(curve.ordb.bit_length(), curve.ordb))
    assert (curve.i * curve.i + 1) % curve.q == 0
    assert curve.b * curve.ordb == Ed25519Point(0, 1)

    montgomery_b = curve.b.to_montgomery()
    print("* B on Montgomery curve: {}".format(montgomery_b))
    assert montgomery_b.x == 9
    assert montgomery_b.to_edwards() == curve.b
    assert montgomery_b * curve.ordb == Montgomery25519Point(None, None)

    print("")

    print("Signing test message:")
    test_message = b'Hello, world! This is a test.'
    secret_key = os.urandom(32)
    print("* secret key({}): {}{}{}".format(len(secret_key) * 8, color_red, xx(secret_key), color_norm))
    public_key = curve.public_key(secret_key)
    print("* public key({}): {}{}{}".format(len(public_key) * 8, color_green, xx(public_key), color_norm))
    sign = curve.sign(test_message, secret_key)
    print("* signature({}): {}{}{}".format(len(sign) * 8, color_green, xx(sign), color_norm))
    curve.check_signature(test_message, sign, public_key)

    # Show the signature and verification process
    bits = curve.bits
    ordb = curve.ordb
    privkey = curve.private_key(secret_key)
    sec_h = curve.hash(secret_key)
    r = curve.hash_int(sec_h[bits // 8:bits // 4] + test_message)
    print("  * r = H(H(secret)[{}:{}] || msg)({}) = {}{:#x}{}".format(
        bits // 8, bits // 4, r.bit_length(), color_red, r, color_norm))
    r_point = curve.b * r
    print("  * B*r = {}{}{}".format(color_green, r_point, color_norm))
    r_point_bin = r_point.encode()
    print("  * encoded B*r({}) = {}{}{}".format(len(r_point_bin) * 8, color_green, xx(r_point_bin), color_norm))
    hash_for_s = curve.hash_int(r_point_bin + public_key + test_message) % ordb
    print("  * H(B*r || pubkey || msg)({}) = {}{:#x}{}".format(
        hash_for_s.bit_length() * 8, color_green, hash_for_s, color_norm))
    s = (r + privkey * hash_for_s) % ordb
    print("  * s = r + privkey*hash({}) = {}{:#x}{}".format(s.bit_length(), color_green, s, color_norm))
    s_bin = encode_bigint_le(s, bits // 8)
    print("  * encoded s({}) = {}{}{}".format(len(s_bin) * 8, color_green, xx(s_bin), color_norm))
    assert sign == r_point_bin + encode_bigint_le(s, bits // 8)
    pk_point = Ed25519Point.decode(public_key)
    test_point = r_point + (pk_point * hash_for_s)
    print("  * test point = B*r + Pubkey*hash: {}{}{}".format(color_green, test_point, color_norm))
    bs_point = curve.b * s
    print("  * B*s: {}{}{}".format(color_green, bs_point, color_norm))
    assert test_point == bs_point

    return True


def run_ssh_test(colorize):
    """Parse Ed25519 OpenSSH keys"""
    color_red = COLOR_RED if colorize else ''
    color_green = COLOR_GREEN if colorize else ''
    color_norm = COLOR_NORM if colorize else ''
    color_purple = COLOR_PURPLE if colorize else ''

    curve = Ed25519()

    temporary_dir = tempfile.mkdtemp(suffix='_ssh-test')
    logger.debug("Created temporary directory %s/", temporary_dir)
    id_key_path = os.path.join(temporary_dir, 'id_ed25519')
    id_pub_path = os.path.join(temporary_dir, 'id_ed25519.pub')
    try:
        try:
            result = run_process_with_input([
                'ssh-keygen',
                '-t', 'ed25519',
                '-N', '',
                '-f', id_key_path,
            ], b'', color=color_purple)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                print("... ssh-keygen is not installed, skipping the test.")
                return True
            raise
        if not result:
            logger.error("ssh-keygen failed, probably because ed25519 keytype is not supported. Skipping the test.")
            return True

        with open(id_pub_path, 'r') as fpub:
            pubkey_lines = fpub.readlines()
        with open(id_key_path, 'r') as fpriv:
            privkey_lines = fpriv.readlines()

        def pop_string(key, offset):
            """Pop a string from the private key"""
            field_size = struct.unpack('>I', key[offset:offset + 4])[0]
            offset += 4
            assert offset + field_size <= len(key)
            value = key[offset:offset + field_size]
            offset += field_size
            return value, offset

        # The public key is a single line, with base64-encoded data
        assert len(pubkey_lines) == 1
        assert pubkey_lines[0].startswith('ssh-ed25519 ')
        public_key = base64.b64decode(pubkey_lines[0].split(' ', 2)[1])
        print("SSH public key hexdump:")
        hexdump(public_key, color=color_green)
        print("SSH public key fingerprint: SHA256:{}".format(
            base64.b64encode(hashlib.sha256(public_key).digest()).decode('ascii').rstrip('=')))
        print("SSH public key:")
        algorithm, offset = pop_string(public_key, offset=0)
        print("* algorithm: {}".format(repr(algorithm.decode('ascii'))))
        assert algorithm == b'ssh-ed25519'
        pubkey_pt_bin, offset = pop_string(public_key, offset)
        pubkey_pt = Ed25519Point.decode(pubkey_pt_bin)
        print("* public key point: {}{}{}".format(color_green, pubkey_pt, color_norm))
        assert offset == len(public_key)

        print("")

        # The private key is base64-encoded
        assert privkey_lines[0] == '-----BEGIN OPENSSH PRIVATE KEY-----\n'
        assert privkey_lines[-1] == '-----END OPENSSH PRIVATE KEY-----\n'
        private_key = base64.b64decode(''.join(privkey_lines[1:-1]))
        print("SSH private key hexdump:")
        hexdump(private_key, color=color_red)

        # https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key
        if not private_key.startswith(b'openssh-key-v1\0'):
            logger.error("Unsupported private key format")
            return False

        print("SSH private key:")
        offset = len(b'openssh-key-v1\0')
        ciphername, offset = pop_string(private_key, offset)
        print("* ciphername: {}".format(repr(ciphername.decode('ascii'))))
        assert ciphername == b'none'
        kdfname, offset = pop_string(private_key, offset)
        print("* kdfname: {}".format(repr(kdfname.decode('ascii'))))
        assert kdfname == b'none'
        kdfoptions, offset = pop_string(private_key, offset)
        print("* kdfoptions: {}".format(repr(kdfoptions.decode('ascii'))))
        assert kdfoptions == b''
        numkeys = struct.unpack('>I', private_key[offset:offset + 4])[0]
        offset += 4
        print("* numkeys: {}".format(numkeys))
        assert numkeys == 1
        priv_pubkey, offset = pop_string(private_key, offset)
        print("* public key:")
        hexdump(priv_pubkey, color=color_green)
        assert priv_pubkey == public_key
        priv_privkey, offset = pop_string(private_key, offset)
        print("* private key:")
        hexdump(priv_privkey, color=color_red)
        assert offset == len(private_key)

        checkint1, checkint2 = struct.unpack('<II', priv_privkey[:8])
        offset = 8
        print("  * checkint1 = {:#x}".format(checkint1))
        print("  * checkint2 = {:#x}".format(checkint2))
        assert checkint1 == checkint2
        algorithm, offset = pop_string(priv_privkey, offset)
        print("  * algorithm: {}".format(repr(algorithm.decode('ascii'))))
        assert algorithm == b'ssh-ed25519'
        priv_pubkey_pt_bin, offset = pop_string(priv_privkey, offset)
        priv_pubkey_pt = Ed25519Point.decode(priv_pubkey_pt_bin)
        print("  * public key point: {}{}{}".format(color_green, priv_pubkey_pt, color_norm))
        assert len(priv_pubkey_pt_bin) == 32
        assert priv_pubkey_pt_bin == pubkey_pt_bin
        assert priv_pubkey_pt == pubkey_pt
        privkey_bin, offset = pop_string(priv_privkey, offset)
        assert len(privkey_bin) == 64
        priv_secret_bin = privkey_bin[:32]
        print("  * private key:")
        print("    * secret({}): {}{}{}".format(
            len(priv_secret_bin) * 8, color_red, xx(priv_secret_bin), color_norm))
        real_private_key = curve.private_key(priv_secret_bin)
        print("      * private key({}): {}{:#x}{}".format(
            real_private_key.bit_length(), color_red, real_private_key, color_norm))
        print("    * public key({}): {}{}{}".format(
            len(privkey_bin[32:]) * 8, color_green, xx(privkey_bin[32:]), color_norm))
        assert privkey_bin[32:] == pubkey_pt_bin

        comment, offset = pop_string(priv_privkey, offset)
        print("  * comment: {}".format(repr(comment)))
        padding = priv_privkey[offset:]
        print("  * padding: {}".format(xx(padding)))
        assert all(struct.unpack('B', padding[i:i + 1])[0] == i + 1 for i in range(len(padding)))

        # Ensure consistency between public and private keys
        assert curve.b * real_private_key == pubkey_pt
        assert curve.public_key(priv_secret_bin) == pubkey_pt_bin

    finally:
        try:
            os.remove(id_key_path)
            os.remove(id_pub_path)
        except OSError as exc:
            # If removing the files failed, the error will appear in rmdir
            logger.debug("Error while removing files: %r", exc)
        os.rmdir(temporary_dir)
    return True


def main(argv=None):
    """Program entry point"""
    parser = argparse.ArgumentParser(
        description="Perform operations related to Ed25519")
    parser.add_argument('-c', '--color', action='store_true',
                        help="colorize the output")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")

    args = parser.parse_args(argv)
    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    if not run_test(args.color):
        return 1
    print("")
    if not run_ssh_test(args.color):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
