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
"""Perform some DSA-related operations

Digital Signature Algorithm, used by NIST in DSS (FIPS 186). Standard revisions:
* in 1996: FIPS 186-1, https://csrc.nist.gov/publications/detail/fips/186/1/archive/1998-12-15
* in 2000: FIPS 186-2, https://csrc.nist.gov/csrc/media/publications/fips/186/2/archive/2000-01-27/documents/fips186-2.pdf
* in 2009: FIPS 186-3, https://csrc.nist.gov/csrc/media/publications/fips/186/3/archive/2009-06-25/documents/fips_186-3.pdf
* in 2013: FIPS 186-4, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

Parameters:
* L, N = key lengths (for example L = 1024, N = 160)
* q = N-bit prime
* p = L-bit prime such that p − 1 is a multiple of q
* g a number which multiplicative order modulo p is q (ie. g^q = 1 mod p ; as q is prime this makes q the order)
  For example g = h^((p − 1)/q) mod p for some h like 2

Keys:
* 0 < privkey < q
* Pubkey = g^privkey mod p

Signature with private key:
* Choose k randomly, 1 < k < q
  (for example k is obtained from a HMAC with the private key,
  like https://tools.ietf.org/html/rfc6979, Deterministic Usage of DSA and ECDSA))
* Compute r = (g^k mod p) mod q
* If r = 0, choose another k
* Compute s = (Hash(message) + r * privkey) / k mod q (using modular inversion of k)
* If s = 0, choose another k
* The signature is (r, s)

Verification with public key:
* Compute w = 1/s mod q
* Compute u_1 = Hash(message) * w mod q
* Compute u_2 = r * w mod q
* Compute v = (g^u_1 * Pubkey^u_2 mod p) mod q
* Verify that v = r

Proof:
* v = (g^u_1 * Pubkey^u_2 mod p) mod q
    = ( g^( Hash(message) * w ) * g^( privkey * r * w ) mod p) mod q
    = ( g^( (Hash(message) + r * privkey) * w ) mod p) mod q
    = ( g^( k * s * w ) mod p) mod q
    = ( g^k mod p) mod q
    = r

If the same k is used to sign two messages, m1 and m2, with signatures (r1,s1) and (r2,s2):
* r1 = r2 (r only depends on g, k, p and q, not on the key or on the message)
* The function s->h is affine (h = k * s + constant mod q) so its parameters are known...
* k = (H(m2) - H(m1)) / (s1 - s2) mod q
* privkey = (k * s1 - H(m1)) / r1 mod q
so the private key is compromised
"""
import argparse
import base64
import binascii
import hashlib
import logging
import os
import subprocess
import sys
import tempfile

import Crypto.PublicKey.DSA
import Crypto.Signature.DSS
import Crypto.Hash.SHA512
import Crypto.Random.random
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
    # pylint: disable=invalid-name,unused-variable
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m


def decode_bigint_be(data):
    """Decode a Big-Endian big integer"""
    return int(binascii.hexlify(data).decode('ascii'), 16)


def encode_bigint_be(value, bytelen=None):
    """Encode a Big-Endian big integer"""
    if bytelen is None:
        bytelen = (value.bit_length() + 7) // 8
    hexval = '{{:0{:d}x}}'.format(bytelen * 2).format(value)
    return binascii.unhexlify(hexval.encode('ascii'))


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


def run_pycrypto_test(bits, colorize):
    """Perform some DSA things with python-crypto"""
    color_red = COLOR_RED if colorize else ''
    color_green = COLOR_GREEN if colorize else ''
    color_norm = COLOR_NORM if colorize else ''

    logger.debug("Generate a DSA-%d key with PyCrypto", bits)
    key = Crypto.PublicKey.DSA.generate(bits)
    pubkey = key.publickey()
    print("DSA-{} PyCrypto-generated key:".format(bits))
    print("  y({}) = {}{:#x}{}".format(key.y.bit_length(), color_green, key.y, color_norm))
    print("  g({}) = {}{:#x}{}".format(key.g.bit_length(), color_green, key.g, color_norm))
    print("  p({}) = {}{:#x}{}".format(key.p.bit_length(), color_green, key.p, color_norm))
    print("  q({}) = {}{:#x}{}".format(key.q.bit_length(), color_green, key.q, color_norm))
    print("  x({}) = {}{:#x}{}".format(key.x.bit_length(), color_red, key.x, color_norm))
    p_1_q = (key.p - 1) // key.q
    print("  (p-1)/q ({}) = {}{:#x}{}".format(p_1_q.bit_length(), color_green, p_1_q, color_norm))
    print("")

    # Sanity checks
    assert (key.p - 1) % key.q == 0
    assert 1 < key.g < key.p - 1
    assert pow(key.g, key.q, key.p) == 1
    assert 1 < key.x < key.q - 1
    assert pow(key.g, key.x, key.p) == key.y
    assert pow(key.y, key.q, key.p) == 1  # Check the public key against the parameters

    # Compute the size of the key order in bytes
    # It is always 20 (160 bits) in practise
    key_order_bytes = (key.x.bit_length() + 7) // 8
    assert key_order_bytes == 20, "Unexpected order size of {} bytes".format(key_order_bytes)

    # Signature mode can be 'fips-186-3' (random nonce)
    # or 'deterministic-rfc6979' (deterministic nonce)
    signer = Crypto.Signature.DSS.new(key, 'deterministic-rfc6979', encoding='binary')
    verifier = Crypto.Signature.DSS.new(pubkey, 'deterministic-rfc6979', encoding='binary')

    # Test message signature without using Crypto API
    test_message = b'Hello, world! This is a test.'
    h_obj = Crypto.Hash.SHA512.new(test_message)
    h = h_obj.digest()[:key_order_bytes]  # Use truncated hash
    for iteration in range(100):
        k = Crypto.Random.random.StrongRandom().randint(1, key.q - 1)
        r = pow(key.g, k, key.p) % key.q
        if r == 0:
            k = None
            continue
        s1 = ((decode_bigint_be(h) % key.q) + (r * key.x) % key.q) % key.q
        s = (s1 * modinv(k, key.q)) % key.q
        if s == 0:
            k = None
            continue
        break
    assert k
    signature = (r, s)
    print("DSA-SHA512({}):".format(repr(test_message)))
    print("  k({}) = {}{:#x}{}".format(k.bit_length(), color_red, k, color_norm))
    print("  r({}) = {}{:#x}{}".format(r.bit_length(), color_green, r, color_norm))
    print("  s({}) = {}{:#x}{}".format(s.bit_length(), color_green, s, color_norm))

    # Verification
    print("Verification:")
    verifier.verify(h_obj, encode_bigint_be(r) + encode_bigint_be(s))
    w = modinv(s, pubkey.q)
    h = decode_bigint_be(hashlib.sha512(test_message).digest()[:key_order_bytes]) % pubkey.q
    u_1 = (h * w) % pubkey.q
    u_2 = (r * w) % pubkey.q
    v = ((pow(pubkey.g, u_1, pubkey.p) * pow(pubkey.y, u_2, pubkey.p)) % pubkey.p) % pubkey.q
    print("  w({}) = {}{:#x}{}".format(w.bit_length(), color_green, w, color_norm))
    print("  u1({}) = {}{:#x}{}".format(u_1.bit_length(), color_green, u_1, color_norm))
    print("  u2({}) = {}{:#x}{}".format(u_2.bit_length(), color_green, u_2, color_norm))
    print("  v({}) = {}{:#x}{}".format(v.bit_length(), color_green, v, color_norm))
    k_from_priv_key = ((h + r * key.x) * w) % pubkey.q
    print("  k({}) = {}{:#x}{}".format(k_from_priv_key.bit_length(), color_red, k_from_priv_key, color_norm))
    assert v == r
    assert k == k_from_priv_key

    print("")

    # Test message signature using Crypto API
    signature = signer.sign(h_obj)
    assert len(signature) % 2 == 0
    r = decode_bigint_be(signature[:len(signature) // 2])
    s = decode_bigint_be(signature[len(signature) // 2:])
    print("DSS-SHA512 with Crypto:")
    print("  r({}) = {}{:#x}{}".format(r.bit_length(), color_green, r, color_norm))
    print("  s({}) = {}{:#x}{}".format(s.bit_length(), color_green, s, color_norm))

    # Test again, on the signature generated by Crypto.Signature.DSS
    print("Verification of signature generated by Crypto:")
    verifier.verify(h_obj, signature)  # raises ValueError if the signature is incorrect
    w = modinv(s, pubkey.q)
    h = decode_bigint_be(h_obj.digest()[:key_order_bytes]) % pubkey.q
    u_1 = (h * w) % pubkey.q
    u_2 = (r * w) % pubkey.q
    v = ((pow(pubkey.g, u_1, pubkey.p) * pow(pubkey.y, u_2, pubkey.p)) % pubkey.p) % pubkey.q
    print("  w({}) = {}{:#x}{}".format(w.bit_length(), color_green, w, color_norm))
    print("  u1({}) = {}{:#x}{}".format(u_1.bit_length(), color_green, u_1, color_norm))
    print("  u2({}) = {}{:#x}{}".format(u_2.bit_length(), color_green, u_2, color_norm))
    print("  v({}) = {}{:#x}{}".format(v.bit_length(), color_green, v, color_norm))
    k_from_priv_key = ((h + r * key.x) * w) % pubkey.q
    print("  k({}) = {}{:#x}{}".format(k_from_priv_key.bit_length(), color_red, k_from_priv_key, color_norm))
    assert v == r

    return True


def run_openssl_test(bits, colorize):
    """Perform some DSA things with OpenSSL"""
    color_red = COLOR_RED if colorize else ''
    color_green = COLOR_GREEN if colorize else ''
    color_norm = COLOR_NORM if colorize else ''
    color_purple = COLOR_PURPLE if colorize else ''

    temporary_dir = tempfile.mkdtemp(suffix='_dsa-test')
    logger.debug("Created temporary directory %s/", temporary_dir)
    param_path = os.path.join(temporary_dir, 'dsaparam.pem')
    sk_path = os.path.join(temporary_dir, 'sign_key.pem')
    vk_path = os.path.join(temporary_dir, 'verify_key.pem')
    sig_path = os.path.join(temporary_dir, 'message.sign')
    try:
        logger.debug("Generate DSA-%d parameters with OpenSSL", bits)
        result = run_process_with_input(
            ['openssl', 'dsaparam', '-out', param_path, str(bits)],
            b'', color=color_green)
        if not result:
            return False

        with open(param_path, 'r') as fparam:
            param_lines = fparam.readlines()
        colorprint(color_green, ''.join(param_lines))
        assert param_lines[0] == '-----BEGIN DSA PARAMETERS-----\n'
        assert param_lines[-1] == '-----END DSA PARAMETERS-----\n'
        result = run_process_with_input(
            ['openssl', 'asn1parse', '-i', '-dump', '-in', param_path],
            b'', color=color_green)
        if not result:
            return False

        # Decode PEM-encoded ASN.1 parameters
        param_der = base64.b64decode(''.join(param_lines[1:-1]))
        param_asn1 = Crypto.Util.asn1.DerSequence()
        param_asn1.decode(param_der, strict=True)
        assert len(param_asn1) == 3
        param_p, param_q, param_g = param_asn1
        print("DSA-{} OpenSSL-generated parameters:".format(bits))
        print("  p({}) = {}{:#x}{}".format(param_p.bit_length(), color_green, param_p, color_norm))
        print("  q({}) = {}{:#x}{}".format(param_q.bit_length(), color_green, param_q, color_norm))
        print("  g({}) = {}{:#x}{}".format(param_g.bit_length(), color_green, param_g, color_norm))
        assert (param_p - 1) % param_q == 0
        assert 1 < param_g < param_p - 1
        assert pow(param_g, param_q, param_p) == 1

        logger.debug("Generate a DSA-%d key with OpenSSL", bits)
        result = run_process_with_input(
            ['openssl', 'gendsa', '-out', sk_path, param_path],
            b'', color=color_red)
        if not result:
            return False

        with open(sk_path, 'r') as fsk:
            sign_key_lines = fsk.readlines()
        colorprint(color_red, ''.join(sign_key_lines))
        assert sign_key_lines[0] == '-----BEGIN DSA PRIVATE KEY-----\n'
        assert sign_key_lines[-1] == '-----END DSA PRIVATE KEY-----\n'
        result = run_process_with_input(
            ['openssl', 'asn1parse', '-i', '-dump', '-in', sk_path],
            b'', color=color_red)
        if not result:
            return False

        # Decode PEM-encoded ASN.1 key
        sign_key_der = base64.b64decode(''.join(sign_key_lines[1:-1]))
        sign_key_asn1 = Crypto.Util.asn1.DerSequence()
        sign_key_asn1.decode(sign_key_der, strict=True)
        assert len(sign_key_asn1) == 6
        key_zero, key_p, key_q, key_g, key_y, key_x = sign_key_asn1
        print("DSA-{} OpenSSL-generated key:".format(bits))
        print("  y({}) = {}{:#x}{}".format(key_y.bit_length(), color_green, key_y, color_norm))
        print("  x({}) = {}{:#x}{}".format(key_x.bit_length(), color_red, key_x, color_norm))
        assert key_zero == 0
        assert key_p == param_p
        assert key_q == param_q
        assert key_g == param_g
        assert 1 < key_x < key_q - 1
        assert pow(param_g, key_x, param_p) == key_y
        assert pow(key_y, param_q, param_p) == 1

        logger.debug("Generate the public key")
        result = run_process_with_input(
            ['openssl', 'dsa', '-in', sk_path, '-pubout', '-out', vk_path],
            b'', color=color_green)
        if not result:
            return False

        with open(vk_path, 'r') as fvk:
            verify_key_lines = fvk.readlines()
        colorprint(color_green, ''.join(verify_key_lines))
        assert verify_key_lines[0] == '-----BEGIN PUBLIC KEY-----\n'
        assert verify_key_lines[-1] == '-----END PUBLIC KEY-----\n'

        result = run_process_with_input(
            ['openssl', 'asn1parse', '-i', '-dump', '-in', vk_path],
            b'', color=color_green)
        if not result:
            return False

        # Decode PEM-encoded ASN.1 public key
        verify_key_der = base64.b64decode(''.join(verify_key_lines[1:-1]))
        verify_key_asn1 = Crypto.Util.asn1.DerSequence()
        verify_key_asn1.decode(verify_key_der, strict=True)
        assert len(verify_key_asn1) == 2
        verify_key_algo = Crypto.Util.asn1.DerSequence()
        verify_key_algo.decode(verify_key_asn1[0], strict=True)
        assert len(verify_key_algo) == 2
        # OID of dsaEncryption
        assert verify_key_algo[0] == b'\x06\x07\x2a\x86\x48\xce\x38\x04\x01'
        verify_key_params = Crypto.Util.asn1.DerSequence()
        verify_key_params.decode(verify_key_algo[1], strict=True)
        assert len(verify_key_params) == 3
        assert [param_p, param_q, param_g] == list(verify_key_params)
        verify_key_bitstring = Crypto.Util.asn1.DerObject()
        verify_key_bitstring.decode(verify_key_asn1[1], strict=True)
        assert verify_key_bitstring.payload[:1] == b'\0'
        verify_key_pubkey = Crypto.Util.asn1.DerInteger()
        verify_key_pubkey.decode(verify_key_bitstring.payload[1:], strict=True)
        assert key_y == verify_key_pubkey.value

        logger.debug("Sign a message and verify its signature")
        test_message = b'Hello, world! This is a test.'
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
            test_message, color=color_green)
        if not result:
            return False

        with open(sig_path, 'rb') as fsig:
            signature_binary = fsig.read()
        sig_asn1 = Crypto.Util.asn1.DerSequence()
        sig_asn1.decode(signature_binary, strict=True)
        sig_r, sig_s = sig_asn1

        assert 0 < sig_r < param_q
        assert 0 < sig_s < param_q

        # OpenSSL uses truncated SHA-512 hashes (to 160 bits, the size of SHA-1)
        h_msg = decode_bigint_be(hashlib.sha512(test_message).digest()[:20]) % param_q

        print("DSA-SHA512({}):".format(repr(test_message)))
        print("  r({}) = {}{:#x}{}".format(sig_r.bit_length(), color_green, sig_r, color_norm))
        print("  s({}) = {}{:#x}{}".format(sig_s.bit_length(), color_green, sig_s, color_norm))

        w = modinv(sig_s, param_q)
        u_1 = (h_msg * w) % param_q
        u_2 = (sig_r * w) % param_q
        v = ((pow(param_g, u_1, param_p) * pow(key_y, u_2, param_p)) % param_p) % param_q
        print("  w({}) = {}{:#x}{}".format(w.bit_length(), color_green, w, color_norm))
        print("  u1({}) = {}{:#x}{}".format(u_1.bit_length(), color_green, u_1, color_norm))
        print("  u2({}) = {}{:#x}{}".format(u_2.bit_length(), color_green, u_2, color_norm))
        print("  v({}) = {}{:#x}{}".format(v.bit_length(), color_green, v, color_norm))
        assert v == sig_r
        k = ((h_msg + sig_r * key_x) * w) % param_q
        print("  k({}) = {}{:#x}{}".format(k.bit_length(), color_red, k, color_norm))
        assert sig_r == pow(param_g, k, param_p) % param_q

    finally:
        try:
            os.remove(param_path)
            os.remove(sk_path)
            os.remove(vk_path)
            os.remove(sig_path)
        except OSError as exc:
            # If removing the files failed, the error will appear in rmdir
            logger.debug("Error while removing files: %r", exc)
        os.rmdir(temporary_dir)
    return True


def main(argv=None):
    """Program entry point"""
    parser = argparse.ArgumentParser(
        description="Perform operations related to DSA",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-b', '--bits', type=int, default=1024,
                        help="size of the generated DSA key, in bits")
    parser.add_argument('-c', '--color', action='store_true',
                        help="colorize the output")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")

    args = parser.parse_args(argv)
    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    if not run_pycrypto_test(args.bits, args.color):
        return 1
    print("")
    if not run_openssl_test(args.bits, args.color):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
