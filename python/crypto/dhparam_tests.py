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
"""Perform some operations on Diffie-Hellman parameters

Diffie-Hellman parameters consist in:
- a prime number p. It is a strong prime if (p - 1) / 2 is prime too.
- a generator g of the group p. OpenSSL users g = 2 or g = 5.

Documentation:
* https://www.teletrust.de/fileadmin/files/oid/oid_pkcs-3v1-4.pdf
    PKCS #3: Diffie-Hellman KeyAgreement Standard
* https://tools.ietf.org/html/rfc2631
    Diffie-Hellman Key Agreement Method
* https://tools.ietf.org/html/rfc7919
    Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)
    (ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192)
* https://github.com/openssl/openssl/blob/OpenSSL_1_1_1a/crypto/dh/dh_gen.c#L31-L57
    OpenSSL description of its DH parameters generation
* https://wiki.openssl.org/index.php/Diffie-Hellman_parameters
    Diffie-Hellman parameters

Some groups have been standardized:
* https://tools.ietf.org/html/rfc2409
    The Internet Key Exchange (IKE)
    * 1st Oakley Default Group (768 bits): p = 2^768 - 2 ^704 - 1 + 2^64 * { [2^638 pi] + 149686 }, g = 2
    * 2nd Oakley Group (1024 bits): p = 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }, g = 2

* https://tools.ietf.org/html/rfc3526
    More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE):
    * 1536-bit MODP Group (group 5): p = 2^1536 - 2^1472 - 1 + 2^64 * { [2^1406 pi] + 741804 }, g = 2
    * 2048-bit MODP Group (group 14): p = 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }, g = 2
    * 3072-bit MODP Group (group 15): p = 2^3072 - 2^3008 - 1 + 2^64 * { [2^2942 pi] + 1690314 }, g = 2
    * 4096-bit MODP Group (group 16): p = 2^4096 - 2^4032 - 1 + 2^64 * { [2^3966 pi] + 240904 }, g = 2
    * 6144-bit MODP Group (group 17): p = 2^6144 - 2^6080 - 1 + 2^64 * { [2^6014 pi] + 929484 }, g = 2
    * 8192-bit MODP Group (group 18): p = 2^8192 - 2^8128 - 1 + 2^64 * { [2^8062 pi] + 4743158 }, g = 2
"""
import argparse
import base64
import logging
import os
import subprocess
import sys
import tempfile

import Cryptodome.Util.asn1
import Cryptodome.Util.number


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


def run_openssl_test(bits, generator, colorize):
    """Generate Diffie-Hellman parameters with OpenSSL"""
    assert generator in (2, 5)
    color_green = COLOR_GREEN if colorize else ''
    color_norm = COLOR_NORM if colorize else ''

    temporary_dir = tempfile.mkdtemp(suffix='_dhparam-test')
    logger.debug("Created temporary directory %s/", temporary_dir)
    param_path = os.path.join(temporary_dir, 'dhparam.pem')

    try:
        logger.debug("Generate DH-%d parameters (g=%d) with OpenSSL", bits, generator)
        result = run_process_with_input(
            ['openssl', 'dhparam', '-out', param_path, '-outform', 'PEM', '-{}'.format(generator), str(bits)],
            b'', color=color_green)
        if not result:
            return False

        with open(param_path, 'r') as fparam:
            param_lines = fparam.readlines()
        print("DH parameters in PEM format:")
        colorprint(color_green, ''.join(param_lines).strip('\n'))
        assert param_lines[0] == '-----BEGIN DH PARAMETERS-----\n'
        assert param_lines[-1] == '-----END DH PARAMETERS-----\n'

        result = run_process_with_input(
            ['openssl', 'asn1parse', '-i', '-dump', '-in', param_path],
            b'', color=color_green)
        if not result:
            return False

        result = run_process_with_input(
            ['openssl', 'dhparam', '-noout', '-text', '-in', param_path],
            b'', color=color_green)
        if not result:
            return False

        # Decode PEM-encoded ASN.1 parameters
        param_der = base64.b64decode(''.join(param_lines[1:-1]))
        param_asn1 = Cryptodome.Util.asn1.DerSequence()
        param_asn1.decode(param_der)
        assert len(param_asn1) == 2
        param_p, param_g = param_asn1
        print("DH-{} OpenSSL-generated parameters:".format(bits))
        print("  p({}) = {}{:#x}{}".format(param_p.bit_length(), color_green, param_p, color_norm))
        print("  g({}) = {}{:#x}{}".format(param_g.bit_length(), color_green, param_g, color_norm))
        assert 1 < param_g < param_p - 1
        assert pow(param_g, (param_p - 1) // 2, param_p) == param_p - 1, "The generator is not a quadratic residue"
        assert Cryptodome.Util.number.isPrime(param_p)
        assert Cryptodome.Util.number.isPrime((param_p - 1) // 2)
        assert param_g == generator

        # (p-1)/2 is odd, so p mod 4 = 3.
        # If p mod 3 = 1, 3 divides (p-1), so it divides (p-1)/2 too, which
        # would not be prime. As p mod 3 can not be 0 either, p mod 3 = 2.
        # the Chinese remainder theorem (CRT) allows combining these two results
        # into: p mod 12 = 11
        print("p mod 12 = {} (expected 11)".format(param_p % 12))
        assert param_p % 12 == 11

        # It can be shown that 2 is a quadratic residue modulo p if and only if
        # p mod 8 = 1 or 7. Otherwise, p mod 8 = 3 or 5.
        # If p mod 8 = 5, (p-1)/2 mod 4 = 2 so (p-1)/2 is not prime.
        # Therefore for 2 to be a generator, p mod 8 = 3.
        # With p mod 12 = 11, the CRT gives: p mod 24 = 11
        print("p mod 24 = {} (expected 11 for g=2, maybe 23 otherwise)".format(param_p % 24))
        if generator == 2:
            assert param_p % 24 == 11

        # For generator 5, as (-1)^((5-1)/2)*(p-1)/2) = ((-1)^2)^((p-1)/2) = 1,
        # the Law of quadratic reciprocity results in (p|5)*(5|p) = 1, where
        # (a|b) is the Legendre symbol.
        # For 5 to be a generator, it can not be a quadratic residue modulo p,
        # so (p|5) = -1, which means that -1 = (5|p) = p^2 mod 5.
        # Finally p mod 5 = 2 or 3.
        # With p mod 12 = 11, the CRT gives: p mod 60 = 47 or 23.
        # If g is not 5, p mod 5 cannot be 0 nor 1 (in order for (p-1)/2 to be
        # prime), so the only other possible value for p mod 5 is 4.
        print("p mod 60 = {} (expected 23 or 47 for g=5, maybe 59 otherwise)".format(param_p % 60))
        if generator == 5:
            assert param_p % 60 in (23, 47)
    finally:
        try:
            os.remove(param_path)
        except OSError as exc:
            # If removing the files failed, the error will appear in rmdir
            logger.debug("Error while removing files: %r", exc)
        os.rmdir(temporary_dir)
    return True


def main(argv=None):
    """Program entry point"""
    parser = argparse.ArgumentParser(
        description="Perform operations on DH parameters",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-b', '--bits', type=int, default=256,
                        help="size of the generated DH prime, in bits")
    parser.add_argument('-5', '--gen5', action='store_true',
                        help="use 5 as generator instead of 2")
    parser.add_argument('-c', '--color', action='store_true',
                        help="colorize the output")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")

    args = parser.parse_args(argv)
    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    if not run_openssl_test(args.bits, 5 if args.gen5 else 2, args.color):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
