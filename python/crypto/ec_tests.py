#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2017-2018 Nicolas Iooss
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
"""Perform some operations on Elliptic-Curve

Documentation:
* List of elliptic curves supported by OpenSSL: openssl ecparam -list_curves
* https://safecurves.cr.yp.to/ choosing safe curves for elliptic-curve cryptography
* https://github.com/warner/python-ecdsa Pure-Python ECDSA
* https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf Digital Signature Standard (DSS)
* https://en.wikipedia.org/wiki/ElGamal_encryption ElGamal encryption system
* https://eprint.iacr.org/2015/659.pdf Diversity and Transparency for ECC (from ANSSI's crypto team)

Introductions (from https://github.com/pFarb/awesome-crypto-papers):
* http://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/
* http://andrea.corbellini.name/2015/05/30/elliptic-curve-cryptography-ecdh-and-ecdsa/

@author: Nicolas Iooss
@license: MIT
"""
import argparse
import base64
import binascii
import collections
import errno
import hashlib
import logging
import os.path
import random
import struct
import subprocess
import sys
import tempfile

import Crypto.Util.asn1


logger = logging.getLogger(__name__)


COLOR_RED = '\033[31m'
COLOR_GREEN = '\033[32m'
COLOR_PURPLE = '\033[35m'
COLOR_NORM = '\033[m'


def colorprint(color, text):
    """Print the text in color"""
    if color:
        print('{}{}{}'.format(color, text, COLOR_NORM))
    else:
        print(text)


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
    if sys.version_info < (3, 8):
        # pylint: disable=invalid-name,unused-variable
        g, x, y = extended_gcd(a, m)
        if g != 1:
            raise ValueError
        return x % m
    return pow(a, -1, m)


def mod_sqrt(n, p):
    """Modular square root

    Cipolla's algorithm from https://en.wikipedia.org/wiki/Cipolla%27s_algorithm
    """
    assert pow(n, (p - 1) // 2, p) == 1
    # Find a random "a" which is a quadratic non-residue in F_p
    rnd = random.SystemRandom()
    while True:
        a = rnd.randint(1, p - 1)
        not_square = (a * a - n) % p
        legendre_symbol = pow(not_square, (p - 1) // 2, p)
        if legendre_symbol == p - 1:
            break

    # Compute x = (a + sqrt(a^2 - n))^((p + 1)/2) mod p, so that x^2 = n mod p
    u = a
    v = 1
    e = (p + 1) // 2
    bitmask = 1 << (e.bit_length() - 2)
    while bitmask >= 1:
        # square
        (u, v) = ((u * u + v * v * (a * a - n)) % p, (2 * u * v) % p)
        if e & bitmask:
            # multiply by (a + sqrt(a^2 - n))
            (u, v) = ((u * a + v * (a * a - n)) % p, (u + v * a) % p)
        bitmask = bitmask // 2
    assert v == 0
    return u


def test_mod_sqrt():
    """Test the implementation of modular square root"""
    for prime in (5, 7, 11, 13, 17, 19, 23, 29, 31):
        assert pow(mod_sqrt(4, prime), 2, prime) == 4


test_mod_sqrt()


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


def decode_bigint_be(data):
    """Decode a Big-Endian big integer"""
    if sys.version_info < (3, 2):
        return int(binascii.hexlify(data).decode('ascii'), 16)
    return int.from_bytes(data, 'big')


def encode_bigint_be(value, bytelen=None):
    """Encode a Big-Endian big integer"""
    if bytelen is None:
        bytelen = (value.bit_length() + 7) // 8
    if sys.version_info < (3, 2):
        hexval = '{{:0{:d}x}}'.format(bytelen * 2).format(value)
        return binascii.unhexlify(hexval.encode('ascii'))
    return value.to_bytes(bytelen, 'big')


def run_process_with_input(cmdline, data, color=None):
    """Run the given command with the given data and show its output in colors"""
    print("Output of \"{}\":".format(' '.join(cmdline)))
    if color:
        sys.stdout.write(color)
    sys.stdout.flush()
    proc = subprocess.Popen(cmdline, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
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


class ECPoint(object):
    """A point on an elliptic curve"""
    def __init__(self, curve, x, y, order=None):
        if curve is not None:
            assert curve.has_point(x, y)
        else:
            # Infinity point
            assert x is None
            assert y is None

        self.curve = curve
        self.x = x
        self.y = y
        self.order = order
        if order is not None:
            assert self * order == INFINITY

    def __hash__(self):
        return hash((self.curve, self.x, self.y))

    def __eq__(self, other):
        return self.curve == other.curve and self.x == other.x and self.y == other.y

    def __ne__(self, other):
        return self.curve != other.curve or self.x != other.x or self.y != other.y

    def negate(self):
        """Return the opposite value of the point"""
        if self == INFINITY:
            return INFINITY
        # Use "-y" modulo curve.p
        if not self.y:
            return ECPoint(self.curve, self.x, self.y, self.order)
        return ECPoint(self.curve, self.x, self.curve.p - self.y, self.order)

    def mul_2(self):
        """Compute the double of the point on curve y^2 = x^3 + a*x + b mod p

        The tangent at (x, y) has a slope l := dy/dx = (3x^2 + a) / (2y)
        So its equation for (X, Y) is Y = y + l * (X - x)
        Its intersection with the curve is:

            Y^2 = X^3 + a*X + b
            y^2 + 2*y*l*(X - x) + l^2*(X - x)^2 = X^3 + a*X + b
            (x^3 + a*x + b) + (3*x^2 + a)*(X - x) + l^2*(X - x)^2 = X^3 + a*X + b
            x^3 + 3x^2*(X - x) + l^2*(X - x)^2 = X^3
            3*x^2*(X - x) + l^2*(X - x)^2 = X^3 - x^3
            3*x^2*(X - x) + l^2*(X - x)^2 = (X - x)*(X^2 + x*X + x^2)
        With X != x
            3*x^2 + l^2*(X - x) = X^2 + x*X + x^2
            l^2*(X - x) = X^2 + x*X - 2*x^2
            l^2*(X - x) = (X - x)(X + 2*x)
        With X != x
            l^2 = X + 2*x
            X = l^2 - 2*x
        """
        if self == INFINITY:
            return INFINITY

        p = self.curve.p
        a = self.curve.a
        slope = ((3 * self.x * self.x + a) * modinv(2 * self.y, p)) % p
        x3 = (slope * slope - 2 * self.x) % p
        y3 = (slope * (self.x - x3) - self.y) % p
        return ECPoint(self.curve, x3, y3)

    def __add__(self, other):
        """Add two points on the same curve

        with S=self and O=other and I(X,Y)=intersection, S + O = -I:
        * sy^2 = sx^3 + a*sx + b mod p
        * oy^2 = ox^3 + a*ox + b mod p
        * Y^2 = X^3 + a*X + b mod p

        define l := (oy - sy) / (ox - sx)
        the line joining S, O and I is defined by: Y = sy + l * (X - sx)

        Intersection:
            Y^2 = X^3 + a*X + b
            sy^2 + 2*sy*l*(X - sx) + l^2*(X - sx)^2 = X^3 + a*X + b
            (sx^3 + a*sx + b) + 2*sy*l*(X - sx) + l^2*(X - sx)^2 = X^3 + a*X + b
            2*sy*l*(X - sx) + l^2*(X - sx)^2 = (X - sx)*(X^2 + sx*X + sx^2) + a*(X - sx)
        With X != sx:
            2*sy*l + l^2*(X - sx) = X^2 + sx*X + sx^2 + a
            2*sy*l + l^2*(X - ox + ox - sx) = X^2 + sx*X + sx^2 + a
            2*sy*l + l^2*(X - ox) + l*(oy - sy) = X^2 + sx*X + sx^2 + a
            l*(oy + sy) + l^2*(X - ox) = X^2 + sx*X + sx^2 + a
        With l definition and ox != sx:
            (oy - sy)*(oy + sy) + l^2*(ox - sx)*(X - ox) = (X^2 + sx*X + sx^2 + a)*(ox - sx)
            oy^2 - sy^2 + l^2*(ox - sx)*(X - ox) = (ox - sx)*X^2 + (ox - sx)*sx*X + ox*sx^2 + a*ox - sx^3 - a*sx
            ox^3 + a*ox - sx^3 - a*sx + l^2*(ox - sx)*(X - ox) = ...
            l^2*(ox - sx)*(X - ox) = (ox - sx)*X^2 + (ox - sx)*sx*X + (ox*sx^2 - ox^3)
            l^2*(ox - sx)*(X - ox) = (ox - sx)*X^2 + (ox - sx)*sx*X - ox*(ox + sx)*(ox - sx)
            l^2*(X - ox) = X^2 + sx*X - ox*(ox + sx)
            l^2*(X - ox) = (X - ox)*(X + ox + sx)
        With X != ox:
            l^2 = X + ox + sx
            X = l^2 - sx - ox
        """
        if other == INFINITY:
            return self
        if self == INFINITY:
            return other
        assert self.curve == other.curve

        p = self.curve.p
        if self.x == other.x:
            if (self.y + other.y) % p == 0:
                # self and other are opposite
                return INFINITY
            assert self.y == other.y
            return self.mul_2()

        slope = ((other.y - self.y) * modinv(other.x - self.x, p)) % p
        x3 = (slope * slope - self.x - other.x) % p
        y3 = (slope * (self.x - x3) - self.y) % p
        return ECPoint(self.curve, x3, y3)

    def __sub__(self, other):
        """Subtract a point with another"""
        return self + other.negate()

    def __mul__(self, other):
        """Multiply a point by an integer (exponent)"""
        if self == INFINITY:
            return INFINITY
        e = other
        if self.order:
            e = e % self.order
        if e == 0:
            return INFINITY
        assert e > 0

        # Fast (and insecure) exponentiation
        negative_self = self.negate()
        e3 = 3 * e
        bitmask = 1 << (e3.bit_length() - 2)
        result = self
        while bitmask > 1:
            result = result.mul_2()
            if (e3 & bitmask) != 0 and (e & bitmask) == 0:
                result = result + self
            if (e3 & bitmask) == 0 and (e & bitmask) != 0:
                result = result + negative_self
            bitmask = bitmask // 2
        return result

    def __rmul__(self, other):
        """Reverse multiplication by an integer"""
        return self * other

    def __str__(self):
        if self == INFINITY:
            return 'INFINITY'
        return '({},{})'.format(self.x, self.y)


# Inifinity on all curves
INFINITY = ECPoint(None, None, None)


class StandardCurve(object):
    """Standard elliptic curve"""
    def __init__(self, openssl_name, p, p2, a, b, g_x, g_y, g_order, seed=None, seed_check=None):
        """Define a standard elliptic curve

        Curve: y^2 = x^3 + a*x + b mod p
        G(g_x, g_y) is a point of prime order (g_order)
        """
        assert p == p2
        self.openssl_name = openssl_name
        self.p = p
        self.a = a
        self.b = b
        # Verify that the curve is not singular
        assert (4 * (self.a ** 3) + 27 * (self.b ** 2)) % self.p != 0
        self.g = ECPoint(self, g_x, g_y, g_order)
        if seed is not None:
            self.verify_generation_from_seed(seed, seed_check)

    def has_point(self, x, y):
        assert 0 <= x < self.p
        assert 0 <= y < self.p
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def verify_generation_from_seed(self, seed, seed_check):
        """Verify that the generated parameters come from the given SHA-1 seed"""
        assert 152 < seed.bit_length() <= 160
        plen = self.p.bit_length()
        w = (plen - 1) % 160
        h = hashlib.sha1(encode_bigint_be(seed, 20)).digest()
        hh = encode_bigint_be(decode_bigint_be(h) % (2 ** w))
        for i in range((plen - 1) // 160):
            hh += hashlib.sha1(encode_bigint_be(seed + 1 + i)).digest()

        c = decode_bigint_be(hh)
        assert seed_check == c
        assert (self.b * self.b * c + 27) % self.p == 0

    def __repr__(self):
        return "{}({}, bits={})".format(
            self.__class__.__name__,
            repr(self.openssl_name),
            self.p.bit_length())

    def coord_size(self):
        """Get the size in bytes of a point coordinate"""
        return (self.p.bit_length() + 7) // 8

    def public_point(self, private):
        """Get the public key associated with a private key (as bytes)"""
        return self.g * decode_bigint_be(private)


CURVES = collections.OrderedDict((
    ('NIST P-192', StandardCurve(
        openssl_name='prime192v1',
        p=6277101735386680763835789423207666416083908700390324961279,
        p2=2**192 - 2**64 - 1,
        a=-3,
        b=0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1,
        g_x=0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
        g_y=0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811,
        g_order=6277101735386680763835789423176059013767194773182842284081,
        seed=0x3045ae6fc8422f64ed579528d38120eae12196d5,
        seed_check=0x3099d2bbbfcb2538542dcd5fb078b6ef5f3d6fe2c745de65,
    )),
    ('NIST P-224', StandardCurve(
        openssl_name='secp224r1',
        p=26959946667150639794667015087019630673557916260026308143510066298881,
        p2=2**224 - 2**96 + 1,
        a=-3,
        b=0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4,
        g_x=0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,
        g_y=0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34,
        g_order=26959946667150639794667015087019625940457807714424391721682722368061,
        seed=0xbd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5,
        seed_check=0x5b056c7e11dd68f40469ee7f3c7a7d74f7d121116506d031218291fb,
    )),
    ('NIST P-256', StandardCurve(
        openssl_name='prime256v1',
        p=115792089210356248762697446949407573530086143415290314195533631308867097853951,
        p2=2**256 - 2**224 + 2**192 + 2**96 - 1,
        a=-3,
        b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        g_x=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        g_y=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        g_order=115792089210356248762697446949407573529996955224135760342422259061068512044369,
        seed=0xc49d360886e704936a6678e1139d26b7819f7e90,
        seed_check=0x7efba1662985be9403cb055c75d4f7e0ce8d84a9c5114abcaf3177680104fa0d,
    )),
    ('NIST P-384', StandardCurve(
        openssl_name='secp384r1',
        p=39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319,
        p2=2**384 - 2**128 - 2**96 + 2**32 - 1,
        a=-3,
        b=0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        g_x=0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        g_y=0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
        g_order=39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643,
        seed=0xa335926aa319a27a1d00896a6773a4827acdac73,
        seed_check=0x79d1e655f868f02fff48dcdee14151ddb80643c1406d0ca10dfe6fc52009540a495e8042ea5f744f6e184667cc722483,
    )),
    ('NIST P-521', StandardCurve(
        openssl_name='secp521r1',
        p=6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151,
        p2=2**521 - 1,
        a=-3,
        b=0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
        g_x=0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
        g_y=0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
        g_order=6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449,
        seed=0xd09e8800291cb85396cc6717393284aaa0da64ba,
        seed_check=0x0b48bfa5f420a34949539d2bdfc264eeeeb077688e44fbf0ad8f6d0edb37bd6b533281000518e19f1b9ffbe0fe9ed8a3c2200b8f875e523868c70c1e5bf55bad637,
    )),
    ('Certicom secp256-k1', StandardCurve(
        # Curve from SECG (Standards for Efficient Cryptography Group)
        openssl_name='secp256k1',
        p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
        p2=2**256 - 2**32 - 2**10 + 2**6 - 2**4 - 1,
        a=0,
        b=7,
        g_x=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
        g_y=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
        g_order=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    )),
))


def run_curve_test(curve, colorize):
    """Perform some operations on the given curve"""
    color_red = COLOR_RED if colorize else ''
    color_green = COLOR_GREEN if colorize else ''
    color_norm = COLOR_NORM if colorize else ''
    color_purple = COLOR_PURPLE if colorize else ''

    temporary_dir = tempfile.mkdtemp(suffix='_curve-test')
    logger.debug("Created temporary directory %s/", temporary_dir)
    sk_path = os.path.join(temporary_dir, 'sign_key.pem')
    vk_path = os.path.join(temporary_dir, 'verify_key.pem')
    sig_path = os.path.join(temporary_dir, 'message.sign')
    try:
        logger.debug("Generate a %s key", curve.openssl_name)
        result = run_process_with_input(
            ['openssl', 'ecparam', '-name', curve.openssl_name, '-genkey', '-out', sk_path],
            b'', color=color_red)
        if not result:
            return False

        with open(sk_path, 'r') as fsk:
            sign_key_lines = fsk.readlines()
        colorprint(color_red, ''.join(sign_key_lines))
        assert sign_key_lines[0] == '-----BEGIN EC PARAMETERS-----\n'
        assert sign_key_lines[2] == '-----END EC PARAMETERS-----\n'
        assert sign_key_lines[3] == '-----BEGIN EC PRIVATE KEY-----\n'
        assert sign_key_lines[-1] == '-----END EC PRIVATE KEY-----\n'
        result = run_process_with_input(
            ['openssl', 'asn1parse', '-i', '-dump'],
            ''.join(sign_key_lines[:3]).encode('ascii'), color=color_purple)
        if not result:
            return False
        result = run_process_with_input(
            ['openssl', 'asn1parse', '-i', '-dump'],
            ''.join(sign_key_lines[3:]).encode('ascii'), color=color_red)
        if not result:
            return False

        # Decode PEM-encoded ASN.1 key
        # Doc: Elliptic Curve Private Key Structure https://tools.ietf.org/html/rfc5915
        ec_params_der = base64.b64decode(sign_key_lines[1])
        privkey_der = base64.b64decode(''.join(sign_key_lines[4:-1]))
        privkey_asn1 = Crypto.Util.asn1.DerSequence()
        privkey_asn1.decode(privkey_der)
        assert len(privkey_asn1) == 4
        assert privkey_asn1[0] == 1
        assert privkey_asn1[2] == struct.pack('BB', 0xa0, len(ec_params_der)) + ec_params_der
        privkey_asn1_obj = Crypto.Util.asn1.DerObject()
        privkey_asn1_obj.decode(privkey_asn1[1])
        privkey_asn1_pubcont = Crypto.Util.asn1.DerObject()
        privkey_asn1_pubcont.decode(privkey_asn1[3])
        privkey_asn1_pub = Crypto.Util.asn1.DerObject()
        privkey_asn1_pub.decode(privkey_asn1_pubcont.payload)

        logger.debug("Generate the public key")
        result = run_process_with_input(
            ['openssl', 'ec', '-in', sk_path, '-pubout', '-out', vk_path],
            b'', color=color_green)
        if not result:
            return False

        with open(vk_path, 'r') as fvk:
            verify_key_lines = fvk.readlines()
        colorprint(color_green, ''.join(verify_key_lines))

        result = run_process_with_input(
            ['openssl', 'asn1parse', '-i', '-dump'],
            ''.join(verify_key_lines).encode('ascii'), color=color_green)
        if not result:
            return False

        # Decode PEM-encoded ASN.1 public key and ensure it is matching
        pubkey_der = base64.b64decode(''.join(verify_key_lines[1:-1]))
        pubkey_asn1 = Crypto.Util.asn1.DerSequence()
        pubkey_asn1.decode(pubkey_der)
        assert len(pubkey_asn1) == 2
        pubkey_asn1_pub = Crypto.Util.asn1.DerObject()
        pubkey_asn1_pub.decode(pubkey_asn1[1])
        assert pubkey_asn1_pub.payload == privkey_asn1_pub.payload

        # Finish decoding the keys
        privkey = decode_bigint_be(privkey_asn1_obj.payload)
        zero, compress_mode = struct.unpack('BB', privkey_asn1_pub.payload[:2])
        assert zero == 0
        if compress_mode != 4:
            logger.error("Unsupported compressed key (mode %d)", compress_mode)
            return False
        coord_size = curve.coord_size()
        assert len(privkey_asn1_pub.payload) == 2 + 2 * coord_size
        pubkey_x = decode_bigint_be(privkey_asn1_pub.payload[2:2 + coord_size])
        pubkey_y = decode_bigint_be(privkey_asn1_pub.payload[2 + coord_size:])
        print("{} key:".format(curve.openssl_name))
        print("  priv({}) = {}{:#x}{}".format(privkey.bit_length(), color_red, privkey, color_norm))
        print("  pub_x({}) = {}{:#x}{}".format(pubkey_x.bit_length(), color_green, pubkey_x, color_norm))
        print("  pub_y({}) = {}{:#x}{}".format(pubkey_y.bit_length(), color_green, pubkey_y, color_norm))
        assert privkey < curve.g.order
        pubkey = ECPoint(curve, pubkey_x, pubkey_y)
        assert curve.g * privkey == pubkey

        # Test message signature/verification with ECDSA (Elliptic Curve Digital Signature Algorithm)
        test_message = b'Hello, world! This is a test.'
        logger.debug("Sign the test message")
        result = run_process_with_input(
            ['openssl', 'dgst', '-sha512', '-sign', sk_path, '-out', sig_path],
            test_message, color=color_purple)
        if not result:
            return False
        result = run_process_with_input(
            ['openssl', 'dgst', '-sha512', '-verify', vk_path, '-signature', sig_path],
            test_message, color=color_purple)
        if not result:
            return False
        result = run_process_with_input(
            ['openssl', 'dgst', '-sha512', '-prverify', sk_path, '-signature', sig_path],
            test_message, color=color_purple)
        if not result:
            return False
        result = run_process_with_input(
            ['openssl', 'asn1parse', '-inform', 'DER', '-i', '-dump', '-in', sig_path],
            b'', color=color_green)
        if not result:
            return False

        # Parameters:
        #   * G = curve.g
        #   * n = curve.g.order
        #   * z = HASH(message) truncated to bit_length(n) highest bits
        # Signature with private key:
        #   * Choose k between 1 and n-1
        #   * Compute (x1, y1) = G * k
        #   * Compute r = x1 mod n
        #   * Ensure that r != 0 (otherwise choose another k)
        #   * Compute s = ((z + r * privkey) / k) mod n
        #   * Ensure that s != 0 (otherwise choose another k)
        #   * The signature is (r, s)
        # Verification with public key:
        #   * Compute w = 1/s mod n
        #   * Compute u_1 = z * w mod n
        #   * Compute u_2 = r * w mod n
        #   * Compute (x1, y1) = G * u_1 + Pubkey * u_2
        #   * Verify that x1 % n = r
        # Proof:
        #   G * u_1 + Pubkey * u_2 = G * (z * w) + (G * privkey) * (r * w)
        #       = G * (z * w + privkey * r * w)
        #       = G * ((z + privkey * r) * (1/s))
        #       = G * k
        #       = (x_1, y_1)
        with open(sig_path, 'rb') as fsig:
            signature_binary = fsig.read()
        sig_asn1 = Crypto.Util.asn1.DerSequence()
        sig_asn1.decode(signature_binary)
        sig_r, sig_s = sig_asn1[:]  # noqa
        assert 0 <= sig_r < curve.g.order
        assert 0 <= sig_s < curve.g.order
        z = decode_bigint_be(hashlib.sha512(test_message).digest())
        if curve.p.bit_length() < 512:
            z = z >> (512 - curve.p.bit_length())
        w = modinv(sig_s, curve.g.order)
        u_1 = (z * w) % curve.g.order
        u_2 = (sig_r * w) % curve.g.order
        point = curve.g * u_1 + pubkey * u_2
        assert point.x % curve.g.order == sig_r
        print("ECDSA Signature point: {}({:#x}, {:#x}){}".format(color_green, point.x, point.y, color_norm))

        k = (u_1 + u_2 * privkey) % curve.g.order
        assert point == curve.g * k
        print("ECDSA Signature secret: {}{:#x}{}".format(color_red, k, color_norm))

        # Implement ElGamal encryption
        test_message = b'Hello, world!'
        print("Encrypting the test message (ElGamal):")
        rnd = random.SystemRandom()
        while True:
            msgpoint_x = decode_bigint_be(test_message + struct.pack('<BI', 0, rnd.randint(0, 0xffffffff)))
            assert msgpoint_x % curve.p == msgpoint_x
            msgpoint_y2 = (msgpoint_x * msgpoint_x * msgpoint_x + curve.a * msgpoint_x + curve.b) % curve.p
            # break if y^2 is a square residue modulo p
            if pow(msgpoint_y2, (curve.p - 1) // 2, curve.p) == 1:
                break
            logger.debug("... failed to map to a point")

        msgpoint_y = mod_sqrt(msgpoint_y2, curve.p)
        assert (msgpoint_y * msgpoint_y) % curve.p == msgpoint_y2
        msgpoint = ECPoint(curve, msgpoint_x, msgpoint_y)
        k = rnd.randint(1 << 32, curve.g.order - (1 << 32))
        print("  k({}) = {}{:#x}{}".format(k.bit_length(), color_red, k, color_norm))
        c_1 = curve.g * k
        c_2 = pubkey * k
        encrypted = (c_1, c_2 + msgpoint)
        print("Encrypted message (k = secret rand, e1 = G*k, e2 = PubKey*k + msg):")
        print("  e1.x({}) = {}{:#x}{}".format(encrypted[0].x.bit_length(), color_purple, encrypted[0].x, color_norm))
        print("  e1.y({}) = {}{:#x}{}".format(encrypted[0].y.bit_length(), color_purple, encrypted[0].y, color_norm))
        print("  e2.x({}) = {}{:#x}{}".format(encrypted[1].x.bit_length(), color_purple, encrypted[1].x, color_norm))
        print("  e2.y({}) = {}{:#x}{}".format(encrypted[1].y.bit_length(), color_purple, encrypted[1].y, color_norm))

        print("Decrypt the test message (s = e1*privkey, msg = e2-s):")
        shared_secret = encrypted[0] * privkey
        print("  s.x({}) = {}{:#x}{}".format(shared_secret.x.bit_length(), color_red, shared_secret.x, color_norm))
        print("  s.y({}) = {}{:#x}{}".format(shared_secret.y.bit_length(), color_red, shared_secret.y, color_norm))
        assert shared_secret == c_2
        decrypted_point = encrypted[1] - shared_secret
        decrypted = encode_bigint_be(decrypted_point.x)
        logger.debug("Decrypted message with padding: %r", decrypted)
        assert decrypted[-5:-4] == b'\0'
        decrypted = decrypted[:-5]
        print("Decrypted message: {}".format(repr(decrypted)))
        assert decrypted == test_message

    finally:
        try:
            os.remove(sk_path)
            os.remove(vk_path)
            os.remove(sig_path)
        except OSError as exc:
            # If removing the files failed, the error will appear in rmdir
            logger.debug("Error while removing files: %r", exc)
        os.rmdir(temporary_dir)
    return True


def run_ssh_test(curve, colorize):
    """Parse ECDSA OpenSSH keys"""
    color_red = COLOR_RED if colorize else ''
    color_green = COLOR_GREEN if colorize else ''
    color_norm = COLOR_NORM if colorize else ''
    color_purple = COLOR_PURPLE if colorize else ''

    # Find out a matching key type for the specified curve
    if curve.openssl_name == 'prime256v1':  # NIST P-256
        openssh_key_type = 'ecdsa-sha2-nistp256'
    elif curve.openssl_name == 'secp384r1':  # NIST P-384
        openssh_key_type = 'ecdsa-sha2-nistp384'
    elif curve.openssl_name == 'secp521r1':  # NIST P-521
        openssh_key_type = 'ecdsa-sha2-nistp521'
    else:
        # Skip this test
        logger.warning("Curve %r is not supported by OpenSSH", curve)
        return True

    temporary_dir = tempfile.mkdtemp(suffix='_ssh-test')
    logger.debug("Created temporary directory %s/", temporary_dir)
    id_key_path = os.path.join(temporary_dir, 'id_ecdsa')
    id_pub_path = os.path.join(temporary_dir, 'id_ecdsa.pub')
    try:
        try:
            result = run_process_with_input([
                'ssh-keygen',
                '-t', 'ecdsa',
                '-b', str(curve.g.order.bit_length()),
                '-N', '',
                '-f', id_key_path,
            ], b'', color=color_purple)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                print("... ssh-keygen is not installed, skipping the test.")
                return True
            raise
        if not result:
            logger.error("ssh-keygen failed, probably because ECDSA keytype is not supported. Skipping the test.")
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
        print("SSH public key: {}{}{}".format(color_green, pubkey_lines[0].strip(), color_norm))
        assert pubkey_lines[0].startswith(openssh_key_type + ' ')
        public_key = base64.b64decode(pubkey_lines[0].split(' ', 2)[1])
        print("SSH public key hexdump:")
        hexdump(public_key, color=color_green)
        print("SSH public key fingerprint: {}SHA256:{}{}".format(
            color_green,
            base64.b64encode(hashlib.sha256(public_key).digest()).decode('ascii').rstrip('='),
            color_norm))
        print("SSH public key:")
        algorithm, offset = pop_string(public_key, offset=0)
        print("* algorithm: {}".format(repr(algorithm.decode('ascii'))))
        assert algorithm == openssh_key_type.encode('ascii')
        curve_name, offset = pop_string(public_key, offset)
        print("* curve: {}".format(repr(curve_name.decode('ascii'))))
        assert curve_name == openssh_key_type.split('-')[-1].encode('ascii')
        pubkey_pt_bin, offset = pop_string(public_key, offset)
        coord_size = curve.coord_size()
        assert len(pubkey_pt_bin) == 1 + 2 * coord_size
        compress_mode, = struct.unpack('B', pubkey_pt_bin[:1])
        if compress_mode != 4:
            logger.error("Unsupported compressed key (mode %d)", compress_mode)
            return False
        pubkey_x = decode_bigint_be(pubkey_pt_bin[1:1 + coord_size])
        pubkey_y = decode_bigint_be(pubkey_pt_bin[1 + coord_size:])
        pubkey_pt = ECPoint(curve, pubkey_x, pubkey_y)
        print("* public key point: {}{}{}".format(color_green, pubkey_pt, color_norm))
        assert offset == len(public_key)

        print("")

        # The private key is base64-encoded
        if 'EC PRIVATE KEY' in privkey_lines[0]:
            # The private key is in usual ASN.1 format for OpenSSH < 7.8
            assert privkey_lines[0] == '-----BEGIN EC PRIVATE KEY-----\n'
            assert privkey_lines[-1] == '-----END EC PRIVATE KEY-----\n'
            private_key = base64.b64decode(''.join(privkey_lines[1:-1]))
            print("SSH private key hexdump:")
            hexdump(private_key, color=color_red)
            result = run_process_with_input(
                ['openssl', 'asn1parse', '-i', '-dump'],
                ''.join(privkey_lines[1:-1]).encode('ascii'), color=color_red)
            if not result:
                return False

            privkey_asn1 = Crypto.Util.asn1.DerSequence()
            privkey_asn1.decode(private_key)
            assert len(privkey_asn1) == 4
            assert privkey_asn1[0] == 1
            privkey_asn1_obj = Crypto.Util.asn1.DerObject()
            privkey_asn1_obj.decode(privkey_asn1[1])
            private_key_secret = decode_bigint_be(privkey_asn1_obj.payload)
            print("* private key({}): {}{:#x}{}".format(
                len(privkey_asn1_obj.payload) * 8, color_red, private_key_secret, color_norm))

            privkey_asn1_curvecont = Crypto.Util.asn1.DerObject()
            privkey_asn1_curvecont.decode(privkey_asn1[2])
            privkey_asn1_curve = Crypto.Util.asn1.DerObject()
            privkey_asn1_curve.decode(privkey_asn1_curvecont.payload)
            print("* hexadecimal curve OID: {}".format(
                binascii.hexlify(privkey_asn1_curve.payload).decode('ascii')))

            privkey_asn1_pubcont = Crypto.Util.asn1.DerObject()
            privkey_asn1_pubcont.decode(privkey_asn1[3])
            privkey_asn1_pub = Crypto.Util.asn1.DerObject()
            privkey_asn1_pub.decode(privkey_asn1_pubcont.payload)
            priv_pubkey = privkey_asn1_pub.payload
            print("* public key:")
            hexdump(priv_pubkey, color=color_green)
            assert priv_pubkey == b'\0' + pubkey_pt_bin

        else:
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
            assert algorithm == openssh_key_type.encode('ascii')
            curve_name, offset = pop_string(priv_privkey, offset)
            print("  * curve: {}".format(repr(curve_name.decode('ascii'))))
            assert curve_name == openssh_key_type.split('-')[-1].encode('ascii')
            priv_pubkey_pt_bin, offset = pop_string(priv_privkey, offset)
            compress_mode, = struct.unpack('B', priv_pubkey_pt_bin[:1])
            if compress_mode != 4:
                logger.error("Unsupported compressed key (mode %d)", compress_mode)
                return False
            priv_pubkey_x = decode_bigint_be(priv_pubkey_pt_bin[1:1 + coord_size])
            priv_pubkey_y = decode_bigint_be(priv_pubkey_pt_bin[1 + coord_size:])
            priv_pubkey_pt = ECPoint(curve, priv_pubkey_x, priv_pubkey_y)
            print("  * public key point: {}{}{}".format(color_green, priv_pubkey_pt, color_norm))
            assert len(priv_pubkey_pt_bin) == 1 + 2 * coord_size
            assert priv_pubkey_pt_bin == pubkey_pt_bin
            assert priv_pubkey_pt == pubkey_pt
            privkey_bin, offset = pop_string(priv_privkey, offset)
            private_key_secret = decode_bigint_be(privkey_bin)
            print("  * private key({}): {}{:#x}{}".format(
                len(privkey_bin) * 8, color_red, private_key_secret, color_norm))
            comment, offset = pop_string(priv_privkey, offset)
            print("  * comment: {}".format(repr(comment)))
            padding = priv_privkey[offset:]
            print("  * padding: {}".format(binascii.hexlify(padding).decode('ascii')))
            assert all(struct.unpack('B', padding[i:i + 1])[0] == i + 1 for i in range(len(padding)))

        # Ensure consistency between public and private keys
        assert curve.g * private_key_secret == pubkey_pt

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
        description="Perform operations related to Elliptic Curves",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-C', '--curve', type=str, default='prime256v1',
                        help="curve to use")
    parser.add_argument('-c', '--color', action='store_true',
                        help="colorize the output")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-l', '--list', action='store_true',
                        help="list the known curves")
    parser.add_argument('-t', '--test-all', action='store_true',
                        help="test all the known curves")

    args = parser.parse_args(argv)
    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    if args.list:
        for name, curve in CURVES.items():
            print("{:>10s}: {} ({} bits)".format(curve.openssl_name, name, curve.p.bit_length()))
        return 0

    if args.test_all:
        for name, curve in CURVES.items():
            print("{:>10s}: {} ({} bits)".format(curve.openssl_name, name, curve.p.bit_length()))
            if not run_curve_test(curve, args.color):
                return 1
        return 0

    curve = CURVES.get(args.curve)
    if curve is None:
        possible_curves = [c for c in CURVES.values() if c.openssl_name == args.curve]
        if len(possible_curves) != 1:
            parser.error("Curve not found: {}".format(args.curve))
        curve = possible_curves[0]

    if not run_curve_test(curve, args.color):
        return 1
    if not run_ssh_test(curve, args.color):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
