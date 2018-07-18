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
import hashlib
import logging
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


logger = logging.getLogger(__name__)


COLOR_RED = '\033[31m'
COLOR_GREEN = '\033[32m'
COLOR_PURPLE = '\033[35m'
COLOR_NORM = '\033[m'


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
    return sum(x << (8 * i) for i, x in enumerate(data))


def decode_bigint_be(data):
    """Decode a Big-Endian big integer"""
    return int(binascii.hexlify(data).decode('ascii'), 16)


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


def encode_bigint_be(value, bytelen=None):
    """Encode a Big-Endian big integer"""
    if bytelen is None:
        bytelen = (value.bit_length() + 7) // 8
    hexval = '{{:0{:d}x}}'.format(bytelen * 2).format(value)
    return binascii.unhexlify(hexval.encode('ascii'))


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


def xor_bytes(data1, data2):
    """XOR two arrays together"""
    assert len(data1) == len(data2)
    if sys.version_info >= (3,):
        return bytes((x ^ y for x, y in zip(data1, data2)))
    return b''.join([chr(ord(x) ^ ord(y)) for x, y in zip(data1, data2)])


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
    print("  q({}) = {}{:#x}{}".format(key.p.bit_length(), color_red, key.q, color_norm))
    print("  u=1/p mod q ({}) = {}{:#x}{}".format(key.u.bit_length(), color_red, key.u, color_norm))

    dp = key.d % (key.p - 1)
    dq = key.d % (key.q - 1)
    qinv = modinv(key.q, key.p)
    print("  dp = d mod p-1 \"exponent1\"({}) = {}{:#x}{}".format(dp.bit_length(), color_red, dp, color_norm))
    print("  dq = d mod q-1 \"exponent2\"({}) = {}{:#x}{}".format(dq.bit_length(), color_red, dq, color_norm))
    print("  qInv = 1/q mod p \"coefficient\"({}) = {}{:#x}{}".format(qinv.bit_length(), color_red, qinv, color_norm))

    # Sanity checks
    assert key.p * key.q == key.n
    phi_n = (key.p - 1) * (key.q - 1)
    assert (key.e * key.d) % phi_n == 1
    assert (key.p * key.u) % key.q == 1
    assert modinv(key.d, phi_n) == key.e
    assert modinv(key.e, phi_n) == key.d
    assert modinv(key.p, key.q) == key.u

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

    # Test message encryption/decryption
    test_message = b'Hello, world! This is a test.'
    print("RSA_textbook_encrypt({}):".format(repr(test_message)))
    ciphertext, = pubkey.encrypt(test_message, 0)
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
        hashlib_hash = hashlib.sha1
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
        result = run_process_with_input([
            'ssh-keygen',
            '-t', 'rsa',
            '-b', str(bits),
            '-N', '',
            '-f', id_rsa_path,
        ], b'', color=color_purple)
        if not result:
            return False

        with open(id_rsa_pub_path, 'r') as fpub:
            pubkey_lines = fpub.readlines()
        with open(id_rsa_path, 'r') as fpriv:
            privkey_lines = fpriv.readlines()

        # The private key is in usual ASN.1 format
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
        print("SSH private key:")
        print("  n({}) = {}{:#x}{}".format(key.n.bit_length(), color_green, key.n, color_norm))
        print("  d({}) = {}{:#x}{}".format(key.d.bit_length(), color_red, key.d, color_norm))
        print("  e({}) = {}{:#x}{}".format(key.e.bit_length(), color_green, key.e, color_norm))
        print("  p({}) = {}{:#x}{}".format(key.p.bit_length(), color_red, key.p, color_norm))
        print("  q({}) = {}{:#x}{}".format(key.p.bit_length(), color_red, key.q, color_norm))
        print("  u=1/p mod q ({}) = {}{:#x}{}".format(key.u.bit_length(), color_red, key.u, color_norm))

        dp = key.d % (key.p - 1)
        dq = key.d % (key.q - 1)
        qinv = modinv(key.q, key.p)
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
        assert modinv(key.d, phi_n) == key.e
        assert modinv(key.e, phi_n) == key.d
        assert modinv(key.p, key.q) == key.u

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
