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
"""Perform some RSA-related operations

Usage:
* ./crypto_rsa.py -c : use colors
* ./crypto_rsa.py -b 1024 : generate 1024-bit RSA keys
* ./crypto_rsa.py -b 1280 : generate 1280-bit RSA keys (=0x500)

Documentation:
* https://tools.ietf.org/html/rfc8017
    PKCS #1: RSA Cryptography Specifications Version 2.2

@author: Nicolas Iooss
@license: MIT
"""
import argparse
import base64
import binascii
import errno
import hashlib
import itertools
import logging
import math
import os
import subprocess
import struct
import sys
import tempfile

import Crypto.PublicKey.RSA
import Crypto.Cipher.PKCS1_OAEP
import Crypto.Cipher.PKCS1_v1_5
import Crypto.Hash.SHA512
import Crypto.Signature.PKCS1_PSS
import Crypto.Signature.PKCS1_v1_5

try:
    import gmpy2
    HAVE_GMPY2 = True
except ImportError:
    HAVE_GMPY2 = False


logger = logging.getLogger(__name__)


COLOR_RED = '\033[31m'
COLOR_GREEN = '\033[32m'
COLOR_PURPLE = '\033[35m'
COLOR_NORM = '\033[m'


# pylint: disable=invalid-name
def extended_gcd(aa, bb):
    """Extended greatest common divisor

    from https://rosettacode.org/wiki/Modular_inverse#Python

    NB. This implementation is quite inefficient, compared to optimized implementations
    such as libTomMath (https://www.libtom.net/LibTomMath/). The author of this
    library described in a book (http://manual.freeshell.org/ltm/tommath.pdf)
    how inefficient an Euclidean division is and how to avoid it.

    In Python, it would be counter-productive to implement the same algorithm as
    libTomMath. Instead, advertise for native implementations such as gmpy2.invert
    (https://gmpy2.readthedocs.io/en/latest/mpz.html#mpz-functions).
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
        if HAVE_GMPY2:
            return int(gmpy2.invert(a, m))
        # pylint: disable=invalid-name,unused-variable
        g, x, y = extended_gcd(a, m)
        if g != 1:
            raise ValueError
        return x % m
    return pow(a, -1, m)


def checked_modinv(a, m):
    """Modular inverse, with checks

    from https://rosettacode.org/wiki/Modular_inverse#Python
    """
    x = modinv(a, m)
    assert (x * a) % m == 1
    if HAVE_GMPY2:
        # Ensure that the algorithm is correct
        assert x == gmpy2.invert(a, m)
    if sys.version_info >= (3, 8):
        assert x == pow(a, -1, m)
    return x


def lcm(x, y):
    """Least Common Multiple"""
    g, _, _ = extended_gcd(x, y)
    return (x // g) * y


def get_privexp_from_npe(n, p, e, q=None, use_lcm=False):
    """Get the private exponent from a public key (n, e) and a prime of n, p"""
    if q is None:
        q = n // p
    assert p * q == n
    order_mod_n = lcm(p - 1, q - 1) if use_lcm else (p - 1) * (q - 1)
    return modinv(e, order_mod_n)


def get_primes_from_nsum(n, sum_p_q):
    """Get primes (p, q) from their product n and their sum sum_p_q

    Do so by solving a polynom of degree 2:
        (X - p)(X - q) = X^2 - sum_p_q * X + n
    """
    delta = (sum_p_q ** 2) - 4 * n

    if sys.version_info >= (3, 8):  # math.isqrt has been introduced in Python 3.8
        sqrt_min = math.isqrt(delta)
    else:
        # Compute the precise root by dichotomy, because math.sqrt operates on floats
        sqrt_min = 0
        sqrt_max = delta
        while sqrt_min < sqrt_max - 1:
            testing = (sqrt_min + sqrt_max) // 2
            if testing * testing > delta:
                sqrt_max = testing
            elif testing * testing < delta:
                sqrt_min = testing
            else:
                sqrt_min = sqrt_max = testing
        while sqrt_min < sqrt_max and sqrt_min * sqrt_min < delta:
            sqrt_min += 1
    if sqrt_min * sqrt_min != delta:
        # This may happen when the order has not been simplified enough
        raise ValueError

    p = (sum_p_q - sqrt_min) // 2
    q = (sum_p_q + sqrt_min) // 2
    return p, q


def get_primes_from_ned(n, e, d, verbose=False):
    """Get primes (p, q) from a public key (n, e) and the private exponent d

    How does it work?
    - d*e - 1 is a multiple of lcm(p - 1, q - 1), which is the order of the
      group of invertible items of Z/nZ
    - By finding low factors of this number, it is likely to obtain the order
      or a number close to it, because p and q should be strong primes
      (ie. p-1 and q-1 should not have many small factors)
    - (p - 1)*(q - 1) is a multiple of the order, and is equal to:
      (p * q) - p - q + 1 = (n + 1) - (p + q)
    - Therefore (p + q) mod order = (n + 1) mod order
    - As p and q should be strong primes, the order (which is lcm(p - 1, q - 1))
      has much more bits that p and q, so (p + q) < order.
    - This leads to: p + q = (n + 1) mod order. With p * q = n, p and q are the
      roots of (X - p)*(X - q) = X*X - ((n + 1) mod order)*X + n
    - Finding the roots of this polynom in the usual set of integers is easy.

    Another possibility consists in using a number, x, and its order:
    - In the order is even, (x^order) mod n = 1, so n divides (x^order)-1 = (x^(order/2)-1)*(x^(order/2)+1)
    - Therefore two GCD computations may give factors of n, but it may not work.
    """
    current_order = d * e - 1

    # Ensure that d and e are private and public keys
    assert pow(2, current_order, n) == 1
    assert pow(3, current_order, n) == 1
    assert pow(5, current_order, n) == 1

    if verbose:
        print("* d*e - 1 ({}) = {:#x}".format(current_order.bit_length(), current_order))

    # Reduce the order using small factors
    for factor in itertools.chain([2], range(3, 100000, 2)):
        while current_order % factor == 0:
            new_order = current_order // factor
            # The factor could be a factor of the real order, in which case
            # new_order is no longer an order. Perform basic checks in order
            # to keep an order after the reduction
            if pow(2, new_order, n) != 1 or pow(3, new_order, n) != 1 or pow(5, new_order, n) != 1:
                print("* Not reducing by {}".format(factor))
                break
            current_order = new_order
            if verbose:
                print("* Reducing by {} => {} bits".format(factor, current_order.bit_length()))

            # Try to factorize as soon as the order is small enough
            if current_order < n:
                # Acceleration: use the fact that n divides (x^order)-1 = (x^(order/2)-1)*(x^(order/2)+1)
                if (current_order & 1) == 0:
                    for x in (2, 3, 5, 7):
                        if sys.version_info >= (3, 5):  # math.gcd has been introduced in Python 3.5
                            p = math.gcd(pow(x, current_order >> 1, n) - 1, n)
                        else:
                            p = extended_gcd(pow(x, current_order >> 1, n) - 1, n)[0]
                        if 1 < p < n:
                            q = n // p
                            if q < p:
                                p, q = q, p
                            assert q > 1
                            assert p * q == n
                            if verbose:
                                print("* Used ({}**(order/2) - 1) mod n".format(x))
                                print("* Found p({}): {:#x}".format(p.bit_length(), p))
                                print("* Found q({}): {:#x}".format(q.bit_length(), q))
                            return p, q

                sum_p_q = (n + 1) % current_order
                if verbose:
                    print("* Order({}) = {:#x}".format(current_order.bit_length(), current_order))
                    print("* p + q ({}) = {:#x}".format(sum_p_q.bit_length(), sum_p_q))

                try:
                    p, q = get_primes_from_nsum(n, sum_p_q)
                except ValueError:
                    if verbose:
                        print("* ... Unable to find a square root for the discriminant of the polynom")
                    continue

                if verbose:
                    print("* Found p({}): {:#x}".format(p.bit_length(), p))
                    print("* Found q({}): {:#x}".format(q.bit_length(), q))
                    real_order = lcm(p - 1, q - 1)
                    print("* LCM(p-1, q-1)({}): {:#x}".format(real_order.bit_length(), real_order))
                    if current_order > real_order:
                        assert current_order % real_order == 0
                        print("* Missing factor from the order: {}".format(current_order // real_order))
                    elif current_order < real_order:
                        assert real_order % current_order == 0
                        print("* The order has been factorized too much, by: {}".format(real_order // current_order))
                assert p * q == n
                return p, q

    if current_order > n:
        # If the current order is too big, (n + 1) % current_order = n + 1 and the "p and q" will be n and 1
        raise ValueError("Unable to reduce the order enough for factorization")


def privkey_from_npe(n, p, e, q=None, use_lcm=False):
    """Craft a private RSA key from a public key (n, e) and a prime of n, p"""
    if q is None:
        q = n // p
    assert p * q == n
    d = get_privexp_from_npe(n, p, e, q=q, use_lcm=use_lcm)
    return Crypto.PublicKey.RSA.construct((n, e, d, p, q))


def privkey_from_pub_p(pubkey, p, use_lcm=False):
    """Craft a private RSA key from a public key and a prime of n, p"""
    return privkey_from_npe(pubkey.n, p, pubkey.e, use_lcm=use_lcm)


def privkey_from_ned(n, e, d, verbose=False):
    """Craft a private RSA key from a public key (n, e) and a private exponent, d"""
    p, q = get_primes_from_ned(n, e, d, verbose=verbose)
    return Crypto.PublicKey.RSA.construct((n, e, d, p, q))


def privkey_from_pub_d(pubkey, d, verbose=False):
    """Craft a private RSA key from a public key and a private exponent, d"""
    return privkey_from_ned(pubkey.n, pubkey.e, d, verbose=verbose)


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


def decode_bigint_le(data):
    """Decode a Little-Endian big integer"""
    if sys.version_info < (3,):
        return sum(ord(x) << (8 * i) for i, x in enumerate(data))
    if sys.version_info < (3, 2):
        return sum(x << (8 * i) for i, x in enumerate(data))
    return int.from_bytes(data, 'little')


def decode_bigint_be(data):
    """Decode a Big-Endian big integer"""
    if sys.version_info < (3, 2):
        return int(binascii.hexlify(data).decode('ascii'), 16)
    return int.from_bytes(data, 'big')


def encode_bigint_le(value, bytelen=None):
    """Encode a Little-Endian big integer"""
    if bytelen is None:
        bytelen = (value.bit_length() + 7) // 8
    if sys.version_info < (3, 2):
        data = bytearray(bytelen)
        for i in range(bytelen):
            data[i] = value & 0xff
            value >>= 8
        assert value == 0
        return bytes(data)
    return value.to_bytes(bytelen, 'little')


def encode_bigint_be(value, bytelen=None):
    """Encode a Big-Endian big integer"""
    if bytelen is None:
        bytelen = (value.bit_length() + 7) // 8
    if sys.version_info < (3, 2):
        hexval = '{{:0{:d}x}}'.format(bytelen * 2).format(value)
        return binascii.unhexlify(hexval.encode('ascii'))
    return value.to_bytes(bytelen, 'big')


def checked_decode_bigint_be(data):
    """decode_bigint_be + extra checks which tests other functions"""
    value = decode_bigint_be(data)
    assert value == decode_bigint_le(data[::-1])
    assert encode_bigint_be(value, len(data)) == data
    assert encode_bigint_le(value, len(data)) == data[::-1]
    return value


def checked_encode_bigint_be(value, bytelen=None):
    """encode_bigint_be + extra checks which tests other functions"""
    data = encode_bigint_be(value, bytelen)
    assert data == encode_bigint_le(value, bytelen)[::-1]
    assert decode_bigint_be(data) == value
    assert decode_bigint_le(data[::-1]) == value
    return data


def xx(data):
    """One-line hexadecimal representation of binary data"""
    if sys.version_info < (3, 5):
        return binascii.hexlify(data).decode('ascii')
    return data.hex()


def xor_bytes(data1, data2):
    """XOR two arrays together"""
    assert len(data1) == len(data2)
    if sys.version_info >= (3,):
        return bytes((x ^ y for x, y in zip(data1, data2)))
    return b''.join([chr(ord(x) ^ ord(y)) for x, y in zip(data1, data2)])


def save_as_pem(key, filename):
    """Save a RSA public or private key as PEM format"""
    with open(filename, 'wb') as fout:
        fout.write(key.exportKey('PEM'))
        fout.write('\n')


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


def run_openssl_test(bits, colorize):
    """Perform some RSA things with python-crypto and OpenSSL"""
    color_red = COLOR_RED if colorize else ''
    color_green = COLOR_GREEN if colorize else ''
    color_norm = COLOR_NORM if colorize else ''
    color_purple = COLOR_PURPLE if colorize else ''

    logger.debug("Generate a RSA-%d key", bits)
    key = Crypto.PublicKey.RSA.generate(bits)
    print("RSA-{} generated key:".format(bits))
    print("  n({}) = {}{:#x}{}".format(key.n.bit_length(), color_green, key.n, color_norm))
    print("  d({}) = {}{:#x}{}".format(key.d.bit_length(), color_red, key.d, color_norm))
    print("  e({}) = {}{:#x}{}".format(key.e.bit_length(), color_green, key.e, color_norm))
    print("  p({}) = {}{:#x}{}".format(key.p.bit_length(), color_red, key.p, color_norm))
    print("  q({}) = {}{:#x}{}".format(key.q.bit_length(), color_red, key.q, color_norm))
    print("  u=1/p mod q ({}) = {}{:#x}{}".format(key.u.bit_length(), color_red, key.u, color_norm))

    dp = key.d % (key.p - 1)
    dq = key.d % (key.q - 1)
    qinv = checked_modinv(key.q, key.p)
    print("  dp = d mod p-1 \"exponent1\"({}) = {}{:#x}{}".format(dp.bit_length(), color_red, dp, color_norm))
    print("  dq = d mod q-1 \"exponent2\"({}) = {}{:#x}{}".format(dq.bit_length(), color_red, dq, color_norm))
    print("  qInv = 1/q mod p \"coefficient\"({}) = {}{:#x}{}".format(qinv.bit_length(), color_red, qinv, color_norm))

    # Sanity checks
    # Use LCM(p-1, q-1) instead of the totient function (phi(n)), as it is more
    # generic and is used by PyCryptodome
    assert key.p * key.q == key.n
    phi_n = (key.p - 1) * (key.q - 1)
    lcm_p1q1 = lcm(key.p - 1, key.q - 1)
    assert phi_n % lcm_p1q1 == 0
    assert (key.e * key.d) % lcm_p1q1 == 1
    assert (key.p * key.u) % key.q == 1
    assert checked_modinv(key.d, lcm_p1q1) == key.e
    assert checked_modinv(key.e, lcm_p1q1) == key.d or checked_modinv(key.e, phi_n) == key.d
    assert checked_modinv(key.p, key.q) == key.u

    # Export private key
    pemprivkey = key.exportKey('PEM')
    print("Private key in PEM format:")
    print("{}{}{}".format(color_red, pemprivkey.decode('ascii'), color_norm))
    if not run_process_with_input(['openssl', 'rsa', '-noout', '-text'], pemprivkey, color=color_red):
        return False
    print("")

    # Create public key
    pubkey = Crypto.PublicKey.RSA.construct((key.n, key.e))
    pempubkey = pubkey.exportKey('PEM')
    print("Public key in PEM format:")
    print("{}{}{}".format(color_green, pempubkey.decode('ascii'), color_norm))
    if not run_process_with_input(['openssl', 'asn1parse', '-i'], pempubkey, color=color_green):
        return False
    if not run_process_with_input(['openssl', 'rsa', '-noout', '-text', '-pubin'], pempubkey, color=color_green):
        return False
    print("")

    # Recover the private key from a prime
    decoded_pubkey = Crypto.PublicKey.RSA.importKey(pempubkey)
    recovered_privkey_nolcm = privkey_from_pub_p(decoded_pubkey, key.p, use_lcm=False)
    recovered_privkey_lcm = privkey_from_pub_p(decoded_pubkey, key.p, use_lcm=True)
    assert recovered_privkey_nolcm.n == pubkey.n
    assert recovered_privkey_nolcm.e == pubkey.e
    assert recovered_privkey_nolcm.p == key.p
    assert recovered_privkey_nolcm.q == key.q
    assert recovered_privkey_lcm.n == pubkey.n
    assert recovered_privkey_lcm.e == pubkey.e
    assert recovered_privkey_lcm.p == key.p
    assert recovered_privkey_lcm.q == key.q
    assert key.d in (recovered_privkey_nolcm.d, recovered_privkey_lcm.d)

    # Recover the private key from the private exponent
    decoded_pubkey = Crypto.PublicKey.RSA.importKey(pempubkey)
    recovered_privkey = privkey_from_pub_d(decoded_pubkey, key.d, verbose=True)
    assert recovered_privkey.n == pubkey.n
    assert recovered_privkey.e == pubkey.e
    assert recovered_privkey.p == key.p
    assert recovered_privkey.q == key.q
    assert recovered_privkey.d == key.d

    # Test message encryption/decryption
    test_message = b'Hello, world! This is a test.'
    print("RSA_textbook_encrypt({}):".format(repr(test_message)))
    try:
        ciphertext, = pubkey.encrypt(test_message, 0)
    except NotImplementedError:
        # PyCryptodome removed direct use of raw RSA
        ciphertext = checked_encode_bigint_be(pow(checked_decode_bigint_be(test_message), key.e, key.n))
    hexdump(ciphertext, color=color_purple)
    print("Decrypted textbook RSA:")
    cipherint = checked_decode_bigint_be(ciphertext)
    decrypted_msg = checked_encode_bigint_be(pow(cipherint, key.d, key.n))
    hexdump(decrypted_msg)
    assert decrypted_msg == test_message
    print("")

    # Use Public-Key Cryptography Standards (PKCS) with random padding
    # RSAES-PKCS1-v1_5 (encryption) and RSASSA-PKCS1-v1_5 (signature)
    print("PKCS#1 v1.5 RSA_encrypt({}):".format(repr(test_message)))
    cipher = Crypto.Cipher.PKCS1_v1_5.new(pubkey)
    ciphertext = cipher.encrypt(test_message)
    hexdump(ciphertext, color=color_purple)
    print("Decrypted RSAES-PKCS1-v1_5:")
    cipherint = checked_decode_bigint_be(ciphertext)
    decrypted_msg = checked_encode_bigint_be(pow(cipherint, key.d, key.n), bytelen=bits // 8)
    hexdump(decrypted_msg)
    assert decrypted_msg.endswith(b'\x00' + test_message)
    assert decrypted_msg[:2] == b'\x00\x02'
    if sys.version_info >= (3,):
        assert all(x != 0 for x in decrypted_msg[2:-len(test_message) - 1])
    else:
        assert all(x != b'\0' for x in decrypted_msg[2:-len(test_message) - 1])
    print("")

    # Encrypt with Optimal Asymmetric Encryption Padding (OAEP), RSAES-OAEP
    print("PKCS#1 OAEP RSA_encrypt({}):".format(repr(test_message)))
    cipher = Crypto.Cipher.PKCS1_OAEP.new(pubkey)
    ciphertext = cipher.encrypt(test_message)
    hexdump(ciphertext, color=color_purple)
    print("Raw decrypted PKCS#1 OAEP RSA (00 || masked_seed || masked_data_block):")
    cipherint = checked_decode_bigint_be(ciphertext)
    decrypted_msg = checked_encode_bigint_be(pow(cipherint, key.d, key.n), bytelen=bits // 8)
    hexdump(decrypted_msg, color=color_purple)
    assert decrypted_msg.startswith(b'\x00')
    # Decode the OAEP message (00 || masked_seed || masked_data_block) with SHA-1
    masked_seed = decrypted_msg[1:0x15]
    masked_data_block = decrypted_msg[0x15:]
    seed_mask = hashlib.sha1(masked_data_block + b'\x00\x00\x00\x00').digest()
    seed = xor_bytes(masked_seed, seed_mask)
    data_block_mask = b''
    # Implement the Mask Generation Function (MGF) based on SHA-1
    for idx in range(len(masked_data_block) // 0x14 + 1):
        data_block_mask += hashlib.sha1(seed + struct.pack('>I', idx)).digest()
        assert len(data_block_mask) == (idx + 1) * 20
    data_block = xor_bytes(masked_data_block, data_block_mask[:len(masked_data_block)])
    print("Unmasked decrypted PKCS#1 OAEP RSA (H(Label='') || 000...000 || 01 || M):")
    hexdump(data_block)
    hash_label = binascii.unhexlify('da39a3ee5e6b4b0d3255bfef95601890afd80709')
    assert hash_label == hashlib.sha1(b'').digest()
    assert data_block.startswith(hash_label)
    assert data_block.endswith(b'\x01' + test_message)
    if sys.version_info >= (3,):
        assert all(x == 0 for x in data_block[20:-len(test_message) - 1])
    else:
        assert all(x == b'\0' for x in data_block[20:-len(test_message) - 1])
    print("")

    # RSASSA-PKCS1-v1_5
    print("PKCS#1 v1.5 RSA_sign({}):".format(repr(test_message)))
    cipher = Crypto.Signature.PKCS1_v1_5.new(key)
    signature = cipher.sign(Crypto.Hash.SHA512.new(test_message))
    hexdump(signature, color=color_purple)
    print("Decrypted RSASSA-PKCS1-v1_5:")
    signedint = checked_decode_bigint_be(signature)
    decrypted_msg = checked_encode_bigint_be(pow(signedint, pubkey.e, pubkey.n), bytelen=bits // 8)
    hexdump(decrypted_msg)
    # EMSA-PKCS1-v1_5
    # DER object:
    #    0:d=0  hl=2 l=  81 cons: SEQUENCE
    #    2:d=1  hl=2 l=  13 cons:  SEQUENCE
    #    4:d=2  hl=2 l=   9 prim:   OBJECT 2.16.840.1.101.3.4.2.3 = sha512
    #   15:d=2  hl=2 l=   0 prim:   NULL
    #   17:d=1  hl=2 l=  64 prim:  OCTET STRING
    tag_prefix = binascii.unhexlify('3051300d060960864801650304020305000440')
    tag = tag_prefix + hashlib.sha512(test_message).digest()
    ps_len = len(decrypted_msg) - len(tag) - 3
    assert decrypted_msg == b'\x00\x01' + (b'\xff' * ps_len) + b'\x00' + tag
    print("")

    # Sign with Probabilistic Signature Scheme (PSS), RSASSA-PSS
    # Use SHA512 but with 1024-bit keys (not enough room), which uses SHA-1 (the default algorithm)
    if bits == 1024:
        crypto_hash = Crypto.Hash.SHA
        hashlib_hash = hashlib.sha1  # noqa
        salt_len = 20
    else:
        crypto_hash = Crypto.Hash.SHA512
        hashlib_hash = hashlib.sha512
        salt_len = 64
    print("PKCS#1 RSASSA-PSS sign({}):".format(repr(test_message)))
    cipher = Crypto.Signature.PKCS1_PSS.new(key)
    signature = cipher.sign(crypto_hash.new(test_message))
    hexdump(signature, color=color_purple)
    print("Raw decrypted PKCS#1 RSASSA-PSS (masked_data_block || salted_hash || 0xbc):")
    signedint = checked_decode_bigint_be(signature)
    decrypted_msg = checked_encode_bigint_be(pow(signedint, pubkey.e, pubkey.n), bytelen=bits // 8)
    hexdump(decrypted_msg, color=color_purple)
    # EMSA-PSS
    assert decrypted_msg.endswith(b'\xbc')
    masked_data_block = decrypted_msg[:-salt_len - 1]
    salted_hash = decrypted_msg[-salt_len - 1:-1]
    data_block_mask = b''
    for idx in range(len(masked_data_block) // salt_len + 1):
        data_block_mask += hashlib_hash(salted_hash + struct.pack('>I', idx)).digest()
        assert len(data_block_mask) == (idx + 1) * salt_len
    data_block = xor_bytes(masked_data_block, data_block_mask[:len(masked_data_block)])
    print("Unmasked decrypted PKCS#1 RSASSA-PSS (000...000 || 01 || salt) with salted_hash = H(0...0 || M || salt):")
    hexdump(data_block)
    assert data_block.startswith((b'\x00', b'\x80'))
    if sys.version_info >= (3,):
        assert all(x == 0 for x in data_block[1:-salt_len - 1])
    else:
        assert all(x == b'\0' for x in data_block[1:-salt_len - 1])
    assert data_block[-salt_len - 1:-salt_len] == b'\x01'
    salt = data_block[-salt_len:]
    msg_hash = hashlib_hash(test_message).digest()
    assert salted_hash == hashlib_hash(b'\x00' * 8 + msg_hash + salt).digest()

    return True


def decode_openssh_private_key(private_key, colorize):
    """Decode a binary RSA private key in OpenSSH format

    https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key
    """
    color_red = COLOR_RED if colorize else ''
    color_green = COLOR_GREEN if colorize else ''
    color_norm = COLOR_NORM if colorize else ''

    if not private_key.startswith(b'openssh-key-v1\0'):
        logger.error("Unsupported private key format")
        return False

    def pop_string(key, offset):
        """Pop a string from the private key"""
        field_size = struct.unpack('>I', key[offset:offset + 4])[0]
        offset += 4
        assert offset + field_size <= len(key)
        value = key[offset:offset + field_size]
        offset += field_size
        return value, offset

    print("SSH private key file:")
    offset = len(b'openssh-key-v1\0')
    ciphername, offset = pop_string(private_key, offset)
    print("  * ciphername: {}".format(repr(ciphername.decode('ascii'))))
    assert ciphername == b'none'
    kdfname, offset = pop_string(private_key, offset)
    print("  * kdfname: {}".format(repr(kdfname.decode('ascii'))))
    assert kdfname == b'none'
    kdfoptions, offset = pop_string(private_key, offset)
    print("  * kdfoptions: {}".format(repr(kdfoptions.decode('ascii'))))
    assert kdfoptions == b''
    numkeys = struct.unpack('>I', private_key[offset:offset + 4])[0]
    offset += 4
    print("  * numkeys: {}".format(numkeys))
    assert numkeys == 1
    priv_pubkey, offset = pop_string(private_key, offset)
    print("  * public key:")
    hexdump(priv_pubkey, color=color_green)
    priv_privkey, offset = pop_string(private_key, offset)
    print("  * private key:")
    # hexdump(priv_privkey, color=color_red)
    assert offset == len(private_key)

    checkint1, checkint2 = struct.unpack('<II', priv_privkey[:8])
    offset = 8
    print("    * checkint1 = {:#x}".format(checkint1))
    print("    * checkint2 = {:#x}".format(checkint2))
    assert checkint1 == checkint2
    algorithm, offset = pop_string(priv_privkey, offset)
    print("    * algorithm: {}".format(repr(algorithm.decode('ascii'))))
    assert algorithm == b'ssh-rsa'
    privkey_n_bin, offset = pop_string(priv_privkey, offset)
    privkey_n = checked_decode_bigint_be(privkey_n_bin)
    print("    * n({}) = {}{:#x}{}".format(privkey_n.bit_length(), color_green, privkey_n, color_norm))
    privkey_e_bin, offset = pop_string(priv_privkey, offset)
    privkey_e = checked_decode_bigint_be(privkey_e_bin)
    print("    * e({}) = {}{:#x}{}".format(privkey_e.bit_length(), color_green, privkey_e, color_norm))
    privkey_d_bin, offset = pop_string(priv_privkey, offset)
    privkey_d = checked_decode_bigint_be(privkey_d_bin)
    print("    * d({}) = {}{:#x}{}".format(privkey_d.bit_length(), color_red, privkey_d, color_norm))
    privkey_qinv_bin, offset = pop_string(priv_privkey, offset)
    privkey_qinv = checked_decode_bigint_be(privkey_qinv_bin)
    print("    * qInv = 1/q mod p({}) = {}{:#x}{}".format(
        privkey_qinv.bit_length(), color_red, privkey_qinv, color_norm))
    privkey_p_bin, offset = pop_string(priv_privkey, offset)
    privkey_p = checked_decode_bigint_be(privkey_p_bin)
    print("    * p({}) = {}{:#x}{}".format(privkey_p.bit_length(), color_red, privkey_p, color_norm))
    privkey_q_bin, offset = pop_string(priv_privkey, offset)
    privkey_q = checked_decode_bigint_be(privkey_q_bin)
    print("    * q({}) = {}{:#x}{}".format(privkey_q.bit_length(), color_red, privkey_q, color_norm))
    comment, offset = pop_string(priv_privkey, offset)
    print("    * comment: {}".format(repr(comment)))
    padding = priv_privkey[offset:]
    print("    * padding: {}".format(xx(padding)))
    assert all(struct.unpack('B', padding[i:i + 1])[0] == i + 1 for i in range(len(padding)))

    # Sanity checks
    assert privkey_p * privkey_q == privkey_n
    phi_n = (privkey_p - 1) * (privkey_q - 1)
    assert (privkey_e * privkey_d) % phi_n == 1
    assert (privkey_qinv * privkey_q) % privkey_p == 1

    # Python2 requires long values
    if sys.version_info < (3,):
        privkey_e = long(privkey_e)  # noqa

    return Crypto.PublicKey.RSA.construct((privkey_n, privkey_e, privkey_d, privkey_p, privkey_q))


def run_ssh_test(bits, colorize):
    """Perform some RSA things with OpenSSH keys"""
    color_red = COLOR_RED if colorize else ''
    color_green = COLOR_GREEN if colorize else ''
    color_norm = COLOR_NORM if colorize else ''
    color_purple = COLOR_PURPLE if colorize else ''

    temporary_dir = tempfile.mkdtemp(suffix='_ssh-test')
    logger.debug("Created temporary directory %s/", temporary_dir)
    id_rsa_path = os.path.join(temporary_dir, 'id_rsa')
    id_rsa_pub_path = os.path.join(temporary_dir, 'id_rsa.pub')
    try:
        try:
            result = run_process_with_input([
                'ssh-keygen',
                '-t', 'rsa',
                '-b', str(bits),
                '-N', '',
                '-f', id_rsa_path,
            ], b'', color=color_purple)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                print("... ssh-keygen is not installed, skipping the test.")
                return True
            raise
        if not result:
            return False

        with open(id_rsa_pub_path, 'r') as fpub:
            pubkey_lines = fpub.readlines()
        with open(id_rsa_path, 'r') as fpriv:
            privkey_lines = fpriv.readlines()

        if 'RSA' in privkey_lines[0]:
            # The private key is in usual ASN.1 format for OpenSSH < 7.8
            assert privkey_lines[0] == '-----BEGIN RSA PRIVATE KEY-----\n'
            assert privkey_lines[-1] == '-----END RSA PRIVATE KEY-----\n'
            private_key = base64.b64decode(''.join(privkey_lines[1:-1]))
            print("SSH private key hexdump:")
            hexdump(private_key, color=color_red)
            result = run_process_with_input(
                ['openssl', 'rsa', '-noout', '-text', '-inform', 'der'],
                private_key, color=color_red)
            if not result:
                return False
            key = Crypto.PublicKey.RSA.importKey(private_key)
        else:
            # The private key is in OpenSSH format by default since OpenSSH 7.8
            assert privkey_lines[0] == '-----BEGIN OPENSSH PRIVATE KEY-----\n'
            assert privkey_lines[-1] == '-----END OPENSSH PRIVATE KEY-----\n'
            private_key = base64.b64decode(''.join(privkey_lines[1:-1]))
            print("SSH private key hexdump:")
            hexdump(private_key, color=color_red)
            key = decode_openssh_private_key(private_key, colorize)

        print("SSH private key:")
        print("  n({}) = {}{:#x}{}".format(key.n.bit_length(), color_green, key.n, color_norm))
        print("  d({}) = {}{:#x}{}".format(key.d.bit_length(), color_red, key.d, color_norm))
        print("  e({}) = {}{:#x}{}".format(key.e.bit_length(), color_green, key.e, color_norm))
        print("  p({}) = {}{:#x}{}".format(key.p.bit_length(), color_red, key.p, color_norm))
        print("  q({}) = {}{:#x}{}".format(key.p.bit_length(), color_red, key.q, color_norm))
        print("  u=1/p mod q ({}) = {}{:#x}{}".format(key.u.bit_length(), color_red, key.u, color_norm))

        dp = key.d % (key.p - 1)
        dq = key.d % (key.q - 1)
        qinv = checked_modinv(key.q, key.p)
        print("  dp = d mod p-1 \"exponent1\"({}) = {}{:#x}{}".format(
            dp.bit_length(), color_red, dp, color_norm))
        print("  dq = d mod q-1 \"exponent2\"({}) = {}{:#x}{}".format(
            dq.bit_length(), color_red, dq, color_norm))
        print("  qInv = 1/q mod p \"coefficient\"({}) = {}{:#x}{}".format(
            qinv.bit_length(), color_red, qinv, color_norm))

        # Sanity checks
        assert key.p * key.q == key.n
        phi_n = (key.p - 1) * (key.q - 1)
        assert (key.e * key.d) % phi_n == 1
        assert (key.p * key.u) % key.q == 1
        assert checked_modinv(key.d, phi_n) == key.e
        assert checked_modinv(key.e, phi_n) == key.d
        assert checked_modinv(key.p, key.q) == key.u

        # The public key is a single line
        assert len(pubkey_lines) == 1
        assert pubkey_lines[0].startswith('ssh-rsa ')
        print("SSH public key:")
        print("  {}{}{}".format(color_green, pubkey_lines[0].strip(), color_norm))
        public_key = base64.b64decode(pubkey_lines[0].split(' ', 2)[1])
        print("SSH public key hexdump:")
        hexdump(public_key, color=color_green)

        # Decode the public key
        print("SSH public key:")
        offset = 0
        field_index = 0
        while offset + 4 <= len(public_key):
            field_size = struct.unpack('>I', public_key[offset:offset + 4])[0]
            offset += 4
            assert offset + field_size <= len(public_key)
            field_data = public_key[offset:offset + field_size]
            if field_index == 0:
                print("* key type: {}".format(field_data.decode('ascii')))
                assert field_data == b'ssh-rsa'
            elif field_index == 1:
                pubkey_e = decode_bigint_be(field_data)
                print("* e({}) = {}{:#x}{}".format(pubkey_e.bit_length(), color_green, pubkey_e, color_norm))
                assert pubkey_e == key.e
            elif field_index == 2:
                pubkey_n = decode_bigint_be(field_data)
                print("* n({}) = {}{:#x}{}".format(pubkey_n.bit_length(), color_green, pubkey_n, color_norm))
                assert pubkey_n == key.n
            else:
                print("* unknown field {} = {}".format(field_index, repr(field_data)))
            offset += field_size
            field_index += 1
        assert offset == len(public_key)

    finally:
        try:
            os.remove(id_rsa_path)
            os.remove(id_rsa_pub_path)
        except OSError as exc:
            # If removing the files failed, the error will appear in rmdir
            logger.debug("Error while removing files: %r", exc)
        os.rmdir(temporary_dir)
    return True


def main(argv=None):
    """Program entry point"""
    parser = argparse.ArgumentParser(
        description="Perform operations related to RSA",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-b', '--bits', type=int, default=2048,
                        help="size of the generated RSA key, in bits")
    parser.add_argument('-c', '--color', action='store_true',
                        help="colorize the output")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")

    args = parser.parse_args(argv)
    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    if not run_openssl_test(args.bits, args.color):
        return 1
    if not run_ssh_test(args.bits, args.color):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
