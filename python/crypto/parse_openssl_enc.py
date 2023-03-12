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
"""Parse files encrypted using openssl enc

Format of the file:
* 8-byte header "Salted__" (53 61 6c 74 65 64 5f 5f)
* 8-byte salt
* encrypted data

NB. by default, the digest algorithm is:
* MD5 for OpenSSL < 1.1
* SHA256 for OpenSSL >= 1.1, since commit
  https://github.com/openssl/openssl/commit/f8547f62c212837dbf44fb7e2755e5774a59a57b

To be compatible, either "-md md5" or "-md sha256" need to be specified when
invoking command "openssl enc".
"""
import argparse
import binascii
import hashlib
import logging
import re
import subprocess
import sys
import tempfile

import Cryptodome.Cipher.AES
import Cryptodome.Cipher.Blowfish
import Cryptodome.Cipher.DES
import Cryptodome.Cipher.DES3
import Cryptodome.Util.Counter
import Cryptodome.Util.number


logger = logging.getLogger(__name__)


# Define the sizes of the known ciphers
CIPHER_KEY_IV_SIZES = {
    'des-ecb': (8, 0),
    'des-cbc': (8, 8),
    'des-ede-ecb': (16, 0),
    'des-ede-cbc': (16, 8),

    'bf-ecb': (16, 0),
    'bf-cbc': (16, 8),
    'bf-ofb': (16, 8),

    'aes-128-ecb': (16, 0),
    'aes-128-cbc': (16, 16),
    'aes-128-ctr': (16, 16),
    'aes-128-ofb': (16, 16),
    'aes-192-ecb': (24, 0),
    'aes-192-cbc': (24, 16),
    'aes-192-ctr': (24, 16),
    'aes-192-ofb': (24, 16),
    'aes-256-ecb': (32, 0),
    'aes-256-cbc': (32, 16),
    'aes-256-ctr': (32, 16),
    'aes-256-ofb': (32, 16),
}

HASHES = {
    'md5': hashlib.md5,  # noqa
    'sha1': hashlib.sha1,  # noqa
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512,
}


def xx(data):
    """One-line hexadecimal representation of binary data"""
    if sys.version_info < (3, 5):
        return binascii.hexlify(data).decode('ascii')
    return data.hex()


def encrypt_message(message, password, algorithm, hash_name, options=None):
    """Encrypt a message using openssl enc"""
    with tempfile.NamedTemporaryFile(prefix='openssl_enc_test') as ftmp:
        # using "-k password" is deprecated. The new way is "-pass pass:password"
        cmdline = [
            'openssl', 'enc',
            '-' + algorithm,
            '-md', hash_name,
            '-pass', 'pass:' + password,
            '-out', ftmp.name
        ]
        # Print out the key and iv that are used
        cmdline += ['-p']
        if options:
            cmdline += options
        logger.info("Running %s", ' '.join(cmdline))
        proc = subprocess.Popen(cmdline, stdin=subprocess.PIPE)
        proc.stdin.write(message.encode('utf-8'))
        proc.stdin.close()
        ret = proc.wait()
        if ret != 0:
            logger.error("Command %s returned %d", ' '.join(cmdline), ret)
            raise ValueError("openssl enc failed")

        enc_data = ftmp.read()
        if not enc_data:
            raise ValueError("openssl enc did not produce any output")
        return enc_data


def EVP_BytesToKey(hash_name, salt, password, count, dklen):
    """Implement OpenSSL's EVP_BytesToKey function

    Formula: D_i = HASH^count(D_(i-1) || data || salt)
    Result: key || iv = D_0 || D_1 || D_2 || ... until dklen is reached

    https://www.openssl.org/docs/manmaster/man3/EVP_BytesToKey.html
    https://github.com/openssl/openssl/blob/OpenSSL_1_1_1/crypto/evp/evp_key.c#L74
    """
    hash_fct = HASHES[hash_name]
    previous_hash = b''
    result = b''
    while len(result) < dklen:
        new_hash = hash_fct(previous_hash + password + salt).digest()
        for _ in range(1, count):
            new_hash = hash_fct(new_hash).digest()
        result += new_hash
        previous_hash = new_hash
    return result[:dklen]


def parse_salted(enc_data, password, algorithm, hash_name, use_pbkdf2=False, n_iter=None):
    """Parse the result of openssl enc"""
    if not enc_data.startswith(b'Salted__'):
        raise ValueError("Salted magic string not found in encrypted data")
    if len(enc_data) <= 0x10:
        raise ValueError("Salted data is too short")
    salt = enc_data[8:0x10]
    logger.info("Salt: %s", xx(salt))

    key_size, iv_size = CIPHER_KEY_IV_SIZES[algorithm]
    dklen = key_size + iv_size

    if use_pbkdf2:
        if not n_iter:
            # Default value of iter is 10000
            # https://github.com/openssl/openssl/blob/OpenSSL_1_1_1/apps/enc.c#L270
            # By the way, on recent OpenSSL versions, -iter triggers the use of PBKDF2:
            # https://github.com/openssl/openssl/blob/OpenSSL_1_1_1/apps/enc.c#L265
            n_iter = 10000

        logger.info("KDF: PBKDF2(HMAC-%s, iter=%d, dklen=%d)", hash_name.upper(), n_iter, dklen)

        # Compute PKCS5_PBKDF2_HMAC into (key, iv)
        # https://github.com/openssl/openssl/blob/OpenSSL_1_1_1/apps/enc.c#L462
        key_iv = hashlib.pbkdf2_hmac(hash_name, password.encode('utf-8'), salt, n_iter, dklen)
    else:
        # Use deprecated key derivation, EVP_BytesToKey
        if not n_iter:
            n_iter = 1
        kdf_name = hash_name.upper()
        if n_iter != 1:
            kdf_name += '^{}'.format(n_iter)
        logger.info("KDF: EVP_BytesToKey(repeat %s on (digest||pass||salt), dklen=%d)", kdf_name, dklen)
        key_iv = EVP_BytesToKey(hash_name, salt, password.encode('utf-8'), n_iter, dklen)

    key = key_iv[:key_size]
    iv = key_iv[key_size:]
    logger.info("Key: %s", xx(key))
    logger.info("Initialization Vector: %s", xx(iv) if iv else "(none)")

    # Decrypt things
    logger.info("Enc data [%d]: %r", len(enc_data) - 0x10, enc_data[0x10:])

    if algorithm in ('des-ecb', 'des-cbc'):
        # DES
        mode = algorithm[4:]
        if mode == 'ecb':
            crypto_des = Cryptodome.Cipher.DES.new(key, Cryptodome.Cipher.DES.MODE_ECB)
        elif mode == 'cbc':
            crypto_des = Cryptodome.Cipher.DES.new(key, Cryptodome.Cipher.DES.MODE_CBC, iv)
        else:
            raise NotImplementedError("Unimplemented DES mode {}".format(mode))
        return crypto_des.decrypt(enc_data[0x10:])

    if algorithm in ('des-ede-ecb', 'des-ede-cbc'):
        # 3DES
        mode = algorithm[8:]
        if mode == 'ecb':
            crypto_3des = Cryptodome.Cipher.DES3.new(key, Cryptodome.Cipher.DES3.MODE_ECB)
        elif mode == 'cbc':
            crypto_3des = Cryptodome.Cipher.DES3.new(key, Cryptodome.Cipher.DES3.MODE_CBC, iv)
        else:
            raise NotImplementedError("Unimplemented 3DES mode {}".format(mode))
        return crypto_3des.decrypt(enc_data[0x10:])

    m = re.match(r'^bf-([a-z]+)$', algorithm)
    if m:
        # Blowfish
        mode = m.group(1)
        if mode == 'ecb':
            crypto_bf = Cryptodome.Cipher.Blowfish.new(key, Cryptodome.Cipher.Blowfish.MODE_ECB)
        elif mode == 'cbc':
            crypto_bf = Cryptodome.Cipher.Blowfish.new(key, Cryptodome.Cipher.Blowfish.MODE_CBC, iv)
        elif mode == 'ofb':
            crypto_bf = Cryptodome.Cipher.Blowfish.new(key, Cryptodome.Cipher.Blowfish.MODE_OFB, iv)
        else:
            raise NotImplementedError("Unimplemented Blowfish mode {}".format(mode))
        return crypto_bf.decrypt(enc_data[0x10:])

    m = re.match(r'^aes-[0-9]+-([a-z]+)$', algorithm)
    if m:
        # AES
        mode = m.group(1)
        if mode == 'ecb':
            crypto_aes = Cryptodome.Cipher.AES.new(key, Cryptodome.Cipher.AES.MODE_ECB)
        elif mode == 'cbc':
            crypto_aes = Cryptodome.Cipher.AES.new(key, Cryptodome.Cipher.AES.MODE_CBC, iv)
        elif mode == 'ofb':
            crypto_aes = Cryptodome.Cipher.AES.new(key, Cryptodome.Cipher.AES.MODE_OFB, iv)
        elif mode == 'ctr':
            ctr = Cryptodome.Util.Counter.new(
                nbits=iv_size * 8,
                initial_value=Cryptodome.Util.number.bytes_to_long(iv),
                little_endian=False)
            crypto_aes = Cryptodome.Cipher.AES.new(key, Cryptodome.Cipher.AES.MODE_CTR, counter=ctr)
        else:
            raise NotImplementedError("Unimplemented AES mode {}".format(mode))
        return crypto_aes.decrypt(enc_data[0x10:])

    raise NotImplementedError("Unimplemented algorithm {}".format(algorithm))


def main(argv=None):
    """Program entry point"""
    parser = argparse.ArgumentParser(
        description="Parse the output of 'openssl enc'",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-a', '--alg',
                        choices=sorted(CIPHER_KEY_IV_SIZES.keys()),
                        default='aes-256-ctr',
                        help="algorithm to use")
    parser.add_argument('-H', '--hash',
                        choices=sorted(HASHES.keys()),
                        default='sha256',
                        help="digest function to use")
    parser.add_argument('-k', '--password', type=str, default='Passw0rd!',
                        help="encryption password")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-i', '--input', type=str,
                        help="input file to decrypt")
    parser.add_argument('-m', '--msg', type=str, default='Hello, world!',
                        help="message to encrypt")
    parser.add_argument('--pbkdf2', action='store_true',
                        help="use PBKDF2 algorithm")
    parser.add_argument('--iter', metavar='COUNT', type=int,
                        help="use a given number of iterations on the password in deriving the encryption key")

    args = parser.parse_args(argv)
    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    if args.input:
        with open(args.input, 'rb') as fin:
            enc_data = fin.read()
        logger.debug("Parsing file %r (%d bytes)", args.input, len(enc_data))
    else:
        enc_options = []
        if args.pbkdf2:
            enc_options.append('-pbkdf2')
        if args.iter:
            enc_options += ['-iter', str(args.iter)]
        try:
            enc_data = encrypt_message(args.msg, args.password, args.alg, args.hash, enc_options)
        except ValueError as exc:
            logger.fatal("Encrypting the message failed: %s", exc)
            return 1
        logger.debug("Parsing encrypted message (%d bytes): %r", len(enc_data), enc_data)

    try:
        dec_data = parse_salted(
            enc_data, args.password, args.alg, args.hash,
            use_pbkdf2=args.pbkdf2, n_iter=args.iter)
        logger.info("Dec data [%d]: %r", len(dec_data), dec_data)
    except ValueError as exc:
        logger.fatal("Parsing the encrypted message failed: %s", exc)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
