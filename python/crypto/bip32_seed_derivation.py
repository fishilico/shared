#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# Copyright (c) 2020 Nicolas Iooss
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
"""Implement several key derivation algorithms related to cryptocurrencies

Here are some Bitcoin Improvement Proposals that define how to derive the
private key of a wallet from a seed:

* https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
  BIP-0032: Hierarchical Deterministic Wallets (HD Wallets) (2012-02-11)
  Key derivation using secp256k1 (http://www.secg.org/sec2-v2.pdf)

* https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
  BIP-0039: Mnemonic code for generating deterministic keys (2013-09-10)
  Mnemonic to seed using PBKDF2 with:
  - password = mnemonic sentence (in UTF-8 NFKD)
  - salt = "mnemonic" + passphrase (in UTF-8 NFKD)
  - iteration count = 2048
  - pseudo-random function = HMAC-SHA512
  - derive key length = 512 bits (64 bytes)

  -  English wordlist: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt

* https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki
  BIP-0043: Purpose Field for Deterministic Wallets (2014-04-24)
  Structure of m/purpose'/* (in BIP-0032 paths), with purpose' = 44' = 0x8000002C for BIP-0044

* https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
  BIP-0044: Multi-Account Hierarchy for Deterministic Wallets (2014-04-24)

Here are related SatoshiLabs Improvement Proposals:

* https://github.com/satoshilabs/slips/blob/master/slip-0044.md
  SLIP-0044 : Registered coin types for BIP-0044 (2014-07-09)

Here are other websites:

* https://iancoleman.io/bip39
  Mnemonic Code Converter
"""
import binascii
import hashlib
import hmac
import unicodedata

from ec_tests import CURVES


SECP256K1 = CURVES['Certicom secp256-k1']


def bip32derive(derivation_path, seed):
    """Derive a key from a seed according to a BIP-0032 derivation path

    Returns (k, c) with:
    - k being the private key (32 bytes)
    - c being the chain code (32 bytes)
    """
    parts = derivation_path.split('/')
    if parts[0] != 'm':
        raise ValueError("Unexpected derivation path prefix: {}".format(repr(derivation_path)))

    # Compute the master extended key
    master_key = hmac.new(b'Bitcoin seed', seed, 'sha512').digest()

    # Compute (k, c) for each child
    # Store k as an integer, as it is understood as a curve scalar
    kpar = int.from_bytes(master_key[:32], 'big')
    cpar = master_key[32:]
    for child in parts[1:]:
        if child.endswith("'"):
            index = (0x80000000 + int(child[:-1])).to_bytes(4, 'big')
            data = b'\x00' + kpar.to_bytes(32, 'big') + index
        else:
            index = int(child).to_bytes(4, 'big')
            pubkey = SECP256K1.g * kpar
            data = (b'\x03' if pubkey.y & 1 else b'\x02') + pubkey.x.to_bytes(32, 'big') + index

        child_i = hmac.new(cpar, data, 'sha512').digest()
        kpar = (kpar + int.from_bytes(child_i[:32], 'big')) % SECP256K1.g.order
        cpar = child_i[32:]

    return kpar.to_bytes(32, 'big'), cpar


def bip39toseed(sentence, passphrase=None):
    """Compute the deterministic key (seed) associated with a sentence of BIP-0039 mnemonics"""
    sentence = unicodedata.normalize('NFKD', sentence)
    salt = b'mnemonic'
    if passphrase:
        passphrase = unicodedata.normalize('NFKD', passphrase)
        salt += passphrase.encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', sentence.encode('utf-8'), salt, 2048, 64)


# Test vectors from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
BIP32_TEST_VECTORS = (
    {
        'seed': bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
        'keys': (
            (
                "m",
                'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',  # noqa
                'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',  # noqa
            ),
            (
                "m/0'",
                'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',  # noqa
                'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',  # noqa
            ),
            (
                "m/0'/1",
                'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',  # noqa
                'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs',  # noqa
            ),
            (
                "m/0'/1/2'",
                'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',  # noqa
                'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM',  # noqa
            ),
            (
                "m/0'/1/2'/2",
                'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',  # noqa
                'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334',  # noqa
            ),
            (
                "m/0'/1/2'/2/1000000000",
                'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',  # noqa
                'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',  # noqa
            ),
        ),
    },
    {
        'seed': bytes.fromhex('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542'),  # noqa
        'keys': (
            (
                "m",
                'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',  # noqa
                'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U',  # noqa
            ),
            (
                "m/0",
                'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',  # noqa
                'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt',  # noqa
            ),
            (
                "m/0/2147483647'",
                'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a',  # noqa
                'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9',  # noqa
            ),
            (
                "m/0/2147483647'/1",
                'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon',  # noqa
                'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef',  # noqa
            ),
            (
                "m/0/2147483647'/1/2147483646'",
                'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',  # noqa
                'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc',  # noqa
            ),
            (
                "m/0/2147483647'/1/2147483646'/2",
                'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt',  # noqa
                'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j',  # noqa
            ),
        ),
    },
    {
        'seed': bytes.fromhex('4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be'),  # noqa
        'keys': (
            (
                "m",
                'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13',  # noqa
                'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6',  # noqa
            ),
            (
                "m/0'",
                'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y',  # noqa
                'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L',  # noqa
            ),
        ),
    },
)


BASE58_BITCOIN_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
assert len(BASE58_BITCOIN_ALPHABET) == 58


def base58_decode(data, size=None):
    """Decode some data encoded using Base58 bitcoin alphabet"""
    value = 0
    for char in data:
        value = value * 58 + BASE58_BITCOIN_ALPHABET.index(char)
    if size is None:
        size = (value.bit_length() + 7) // 8
    return value.to_bytes(size, 'big')


if __name__ == '__main__':
    # Run test vectors from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
    for test_vector in BIP32_TEST_VECTORS:
        seed = test_vector['seed']
        print("Testing BIP32 test vector {}".format(binascii.hexlify(seed).decode('ascii')))
        for derivation_path, expected_pub, expected_priv in test_vector['keys']:
            key, chaincode = bip32derive(derivation_path, seed)

            pubkey = SECP256K1.g * int.from_bytes(key, 'big')
            pubkey_bytes = (b'\x03' if pubkey.y & 1 else b'\x02') + pubkey.x.to_bytes(32, 'big')

            # Key encoding
            decoded_pub = base58_decode(expected_pub, 0x52)
            decoded_priv = base58_decode(expected_priv, 0x52)
            # Version bytes
            assert decoded_pub[:4] == b'\x04\x88\xb2\x1e'
            assert decoded_priv[:4] == b'\x04\x88\xad\xe4'
            # Depth
            depth = len(derivation_path.split('/')) - 1
            assert decoded_pub[4] == depth
            assert decoded_priv[4] == depth
            # Fingerprint of the parent's key
            # (32 bits of RIPEMD160 of SHA256 of public key)
            # ... not verified but of master
            if derivation_path == 'm':
                assert decoded_pub[5:9] == b'\x00\x00\x00\x00'
                assert decoded_priv[5:9] == b'\x00\x00\x00\x00'
            # Child number
            last_child = derivation_path.rsplit('/', 1)[-1]
            if last_child == 'm':
                child_number = b'\x00\x00\x00\x00'
            elif last_child.endswith("'"):
                child_number = (0x80000000 + int(last_child[:-1])).to_bytes(4, 'big')
            else:
                child_number = int(last_child).to_bytes(4, 'big')
            assert decoded_pub[9:0xd] == child_number
            assert decoded_priv[9:0xd] == child_number
            # Chain code
            assert decoded_pub[0xd:0x2d] == chaincode
            assert decoded_priv[0xd:0x2d] == chaincode
            # Key
            assert decoded_pub[0x2d:0x4e] == pubkey_bytes
            assert decoded_priv[0x2d] == 0
            assert decoded_priv[0x2e:0x4e] == key
            # Double SHA-256 checksum
            checksum = hashlib.sha256(decoded_pub[:0x4e]).digest()
            checksum = hashlib.sha256(checksum).digest()
            assert decoded_pub[0x4e:] == checksum[:4]
            checksum = hashlib.sha256(decoded_priv[:0x4e]).digest()
            checksum = hashlib.sha256(checksum).digest()
            assert decoded_priv[0x4e:] == checksum[:4]

            print("- {}: OK".format(derivation_path))

    # Test mnemonics with 12 words
    mnemonics = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    seed = bip39toseed(mnemonics)
    assert seed == bytes.fromhex(
        '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1' +
        '9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4')

    # Test to derive Monero seed
    secret, chaincode = bip32derive("m/44'/128'/0'/0/0", seed)
    assert secret == bytes.fromhex('db9e57474be8b64118b6acf6ecebd13f8f7c326b3bc1b19f4546573d6bac9dcf')
