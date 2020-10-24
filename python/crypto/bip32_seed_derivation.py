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

* https://github.com/satoshilabs/slips/blob/master/slip-0010.md
  SLIP-0010 : Universal private key derivation from master private key (2016-04-26)
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

from ec_tests import SECP256K1, SECP256R1
from ed25519_tests import Ed25519


ED25519 = Ed25519()


# Curves defined in https://github.com/satoshilabs/slips/blob/master/slip-0010.md
KNOWN_CURVES = {
    'bitcoin': (SECP256K1, b'Bitcoin seed'),
    'ed25519': (ED25519, b'ed25519 seed'),
    'nist p-256': (SECP256R1, b'Nist256p1 seed'),
    'nist256p1': (SECP256R1, b'Nist256p1 seed'),
    'secp256k1': (SECP256K1, b'Bitcoin seed'),
    'secp256r1': (SECP256R1, b'Nist256p1 seed'),
}


def bip32derive(derivation_path, seed, curve='secp256k1'):
    """Derive a key from a seed according to a BIP-0032 derivation path

    Returns (k, c) with:
    - k being the private key (32 bytes)
    - c being the chain code (32 bytes)
    """
    parts = derivation_path.split('/')
    if parts[0] != 'm':
        raise ValueError("Unexpected derivation path prefix: {}".format(repr(derivation_path)))

    try:
        curve_obj, hmac_key = KNOWN_CURVES[curve.lower()]
    except KeyError:
        raise ValueError("Unknown curve name {}".format(repr(curve)))

    while True:
        # Compute the master extended key
        master_key = hmac.new(hmac_key, seed, 'sha512').digest()

        # Compute (k, c) for each child
        # Store k as an integer, as it is understood as a curve scalar
        kpar = int.from_bytes(master_key[:32], 'big')
        cpar = master_key[32:]

        # Retry with a slightly different seed, if the result is invalid
        if curve_obj != ED25519 and (kpar == 0 or kpar >= curve_obj.g.order):
            seed = master_key
            continue
        break

    for child in parts[1:]:
        if child.endswith("'"):
            index = (0x80000000 + int(child[:-1])).to_bytes(4, 'big')
            data = b'\x00' + kpar.to_bytes(32, 'big') + index
        else:
            if curve_obj == ED25519:
                raise ValueError("Ed25519 derivation does not support non-hardened key")
            index = int(child).to_bytes(4, 'big')
            pubkey = curve_obj.g * kpar
            data = (b'\x03' if pubkey.y & 1 else b'\x02') + pubkey.x.to_bytes(32, 'big') + index

        while True:
            child_i = hmac.new(cpar, data, 'sha512').digest()
            if curve_obj == ED25519:
                kpar = int.from_bytes(child_i[:32], 'big')
            else:
                int_ileft = int.from_bytes(child_i[:32], 'big')
                kpar_new = (kpar + int_ileft) % curve_obj.g.order
                if int_ileft >= curve_obj.g.order or kpar_new == 0:
                    # resulting key is invalid, loop
                    data = b'\x01' + child_i[32:] + index
                    continue
                kpar = kpar_new
            break
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


def public_point(private_key, curve='secp256k1'):
    """Retrieve the public key as a point object"""
    try:
        curve_obj = KNOWN_CURVES[curve.lower()][0]
    except KeyError:
        raise ValueError("Unknown curve name {}".format(repr(curve)))
    return curve_obj.public_point(key)


def public_key(private_key, curve='secp256k1'):
    """Retrieve the public key as bytes"""
    try:
        curve_obj = KNOWN_CURVES[curve.lower()][0]
    except KeyError:
        raise ValueError("Unknown curve name {}".format(repr(curve)))
    pubkey = curve_obj.public_point(key)
    if curve_obj == ED25519:
        encoded = pubkey.encode()
        assert encoded == curve_obj.public_key(private_key)
        return b'\x00' + encoded
    return (b'\x03' if pubkey.y & 1 else b'\x02') + pubkey.x.to_bytes(32, 'big')


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


# Test vectors from https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vectors
SLIP0010_TEST_VECTORS = (
    {
        'curve': 'secp256k1',
        'seed': bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
        'keys': (
            (
                "m",
                bytes.fromhex('00000000'),
                bytes.fromhex('873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508'),
                bytes.fromhex('e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35'),
                bytes.fromhex('0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2'),
            ),
            (
                "m/0'",
                bytes.fromhex('3442193e'),
                bytes.fromhex('47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141'),
                bytes.fromhex('edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea'),
                bytes.fromhex('035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56'),
            ),
            (
                "m/0'/1",
                bytes.fromhex('5c1bd648'),
                bytes.fromhex('2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19'),
                bytes.fromhex('3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368'),
                bytes.fromhex('03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c'),
            ),
            (
                "m/0'/1/2'",
                bytes.fromhex('bef5a2f9'),
                bytes.fromhex('04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f'),
                bytes.fromhex('cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca'),
                bytes.fromhex('0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2'),
            ),
            (
                "m/0'/1/2'/2",
                bytes.fromhex('ee7ab90c'),
                bytes.fromhex('cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd'),
                bytes.fromhex('0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4'),
                bytes.fromhex('02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29'),
            ),
            (
                "m/0'/1/2'/2/1000000000",
                bytes.fromhex('d880d7d8'),
                bytes.fromhex('c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e'),
                bytes.fromhex('471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8'),
                bytes.fromhex('022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011'),
            ),
        ),
    },
    {
        'curve': 'nist256p1',
        'seed': bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
        'keys': (
            (
                "m",
                bytes.fromhex('00000000'),
                bytes.fromhex('beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea'),
                bytes.fromhex('612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2'),
                bytes.fromhex('0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8'),
            ),
            (
                "m/0'",
                bytes.fromhex('be6105b5'),
                bytes.fromhex('3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11'),
                bytes.fromhex('6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c'),
                bytes.fromhex('0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c'),
            ),
            (
                "m/0'/1",
                bytes.fromhex('9b02312f'),
                bytes.fromhex('4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c'),
                bytes.fromhex('284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129'),
                bytes.fromhex('03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844'),
            ),
            (
                "m/0'/1/2'",
                bytes.fromhex('b98005c1'),
                bytes.fromhex('98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318'),
                bytes.fromhex('694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7'),
                bytes.fromhex('0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0'),
            ),
            (
                "m/0'/1/2'/2",
                bytes.fromhex('0e9f3274'),
                bytes.fromhex('ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0'),
                bytes.fromhex('5996c37fd3dd2679039b23ed6f70b506c6b56b3cb5e424681fb0fa64caf82aaa'),
                bytes.fromhex('029f871f4cb9e1c97f9f4de9ccd0d4a2f2a171110c61178f84430062230833ff20'),
            ),
            (
                "m/0'/1/2'/2/1000000000",
                bytes.fromhex('8b2b5c4b'),
                bytes.fromhex('b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059'),
                bytes.fromhex('21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119'),
                bytes.fromhex('02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4'),
            ),
        ),
    },
    {
        'curve': 'ed25519',
        'seed': bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
        'keys': (
            (
                "m",
                bytes.fromhex('00000000'),
                bytes.fromhex('90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb'),
                bytes.fromhex('2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7'),
                bytes.fromhex('00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed'),
            ),
            (
                "m/0'",
                bytes.fromhex('ddebc675'),
                bytes.fromhex('8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69'),
                bytes.fromhex('68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3'),
                bytes.fromhex('008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c'),
            ),
            (
                "m/0'/1'",
                bytes.fromhex('13dab143'),
                bytes.fromhex('a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14'),
                bytes.fromhex('b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2'),
                bytes.fromhex('001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187'),
            ),
            (
                "m/0'/1'/2'",
                bytes.fromhex('ebe4cb29'),
                bytes.fromhex('2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c'),
                bytes.fromhex('92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9'),
                bytes.fromhex('00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1'),
            ),
            (
                "m/0'/1'/2'/2'",
                bytes.fromhex('316ec1c6'),
                bytes.fromhex('8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc'),
                bytes.fromhex('30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662'),
                bytes.fromhex('008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c'),
            ),
            (
                "m/0'/1'/2'/2'/1000000000'",
                bytes.fromhex('d6322ccd'),
                bytes.fromhex('68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230'),
                bytes.fromhex('8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793'),
                bytes.fromhex('003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a'),
            ),
        ),
    },
    {
        'curve': 'secp256k1',
        'seed': bytes.fromhex('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542'),  # noqa
        'keys': (
            (
                "m",
                bytes.fromhex('00000000'),
                bytes.fromhex('60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689'),
                bytes.fromhex('4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e'),
                bytes.fromhex('03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7'),
            ),
            (
                "m/0",
                bytes.fromhex('bd16bee5'),
                bytes.fromhex('f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c'),
                bytes.fromhex('abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e'),
                bytes.fromhex('02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea'),
            ),
            (
                "m/0/2147483647'",
                bytes.fromhex('5a61ff8e'),
                bytes.fromhex('be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9'),
                bytes.fromhex('877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93'),
                bytes.fromhex('03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b'),
            ),
            (
                "m/0/2147483647'/1",
                bytes.fromhex('d8ab4937'),
                bytes.fromhex('f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb'),
                bytes.fromhex('704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7'),
                bytes.fromhex('03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9'),
            ),
            (
                "m/0/2147483647'/1/2147483646'",
                bytes.fromhex('78412e3a'),
                bytes.fromhex('637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29'),
                bytes.fromhex('f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d'),
                bytes.fromhex('02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0'),
            ),
            (
                "m/0/2147483647'/1/2147483646'/2",
                bytes.fromhex('31a507b8'),
                bytes.fromhex('9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271'),
                bytes.fromhex('bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23'),
                bytes.fromhex('024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c'),
            ),
        ),
    },
    {
        'curve': 'nist256p1',
        'seed': bytes.fromhex('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542'),  # noqa
        'keys': (
            (
                "m",
                bytes.fromhex('00000000'),
                bytes.fromhex('96cd4465a9644e31528eda3592aa35eb39a9527769ce1855beafc1b81055e75d'),
                bytes.fromhex('eaa31c2e46ca2962227cf21d73a7ef0ce8b31c756897521eb6c7b39796633357'),
                bytes.fromhex('02c9e16154474b3ed5b38218bb0463e008f89ee03e62d22fdcc8014beab25b48fa'),
            ),
            (
                "m/0",
                bytes.fromhex('607f628f'),
                bytes.fromhex('84e9c258bb8557a40e0d041115b376dd55eda99c0042ce29e81ebe4efed9b86a'),
                bytes.fromhex('d7d065f63a62624888500cdb4f88b6d59c2927fee9e6d0cdff9cad555884df6e'),
                bytes.fromhex('039b6df4bece7b6c81e2adfeea4bcf5c8c8a6e40ea7ffa3cf6e8494c61a1fc82cc'),
            ),
            (
                "m/0/2147483647'",
                bytes.fromhex('946d2a54'),
                bytes.fromhex('f235b2bc5c04606ca9c30027a84f353acf4e4683edbd11f635d0dcc1cd106ea6'),
                bytes.fromhex('96d2ec9316746a75e7793684ed01e3d51194d81a42a3276858a5b7376d4b94b9'),
                bytes.fromhex('02f89c5deb1cae4fedc9905f98ae6cbf6cbab120d8cb85d5bd9a91a72f4c068c76'),
            ),
            (
                "m/0/2147483647'/1",
                bytes.fromhex('218182d8'),
                bytes.fromhex('7c0b833106235e452eba79d2bdd58d4086e663bc8cc55e9773d2b5eeda313f3b'),
                bytes.fromhex('974f9096ea6873a915910e82b29d7c338542ccde39d2064d1cc228f371542bbc'),
                bytes.fromhex('03abe0ad54c97c1d654c1852dfdc32d6d3e487e75fa16f0fd6304b9ceae4220c64'),
            ),
            (
                "m/0/2147483647'/1/2147483646'",
                bytes.fromhex('931223e4'),
                bytes.fromhex('5794e616eadaf33413aa309318a26ee0fd5163b70466de7a4512fd4b1a5c9e6a'),
                bytes.fromhex('da29649bbfaff095cd43819eda9a7be74236539a29094cd8336b07ed8d4eff63'),
                bytes.fromhex('03cb8cb067d248691808cd6b5a5a06b48e34ebac4d965cba33e6dc46fe13d9b933'),
            ),
            (
                "m/0/2147483647'/1/2147483646'/2",
                bytes.fromhex('956c4629'),
                bytes.fromhex('3bfb29ee8ac4484f09db09c2079b520ea5616df7820f071a20320366fbe226a7'),
                bytes.fromhex('bb0a77ba01cc31d77205d51d08bd313b979a71ef4de9b062f8958297e746bd67'),
                bytes.fromhex('020ee02e18967237cf62672983b253ee62fa4dd431f8243bfeccdf39dbe181387f'),
            ),
        ),
    },
    {
        'curve': 'ed25519',
        'seed': bytes.fromhex('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542'),  # noqa
        'keys': (
            (
                "m",
                bytes.fromhex('00000000'),
                bytes.fromhex('ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b'),
                bytes.fromhex('171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012'),
                bytes.fromhex('008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a'),
            ),
            (
                "m/0'",
                bytes.fromhex('31981b50'),
                bytes.fromhex('0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d'),
                bytes.fromhex('1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635'),
                bytes.fromhex('0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037'),
            ),
            (
                "m/0'/2147483647'",
                bytes.fromhex('1e9411b1'),
                bytes.fromhex('138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f'),
                bytes.fromhex('ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4'),
                bytes.fromhex('005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d'),
            ),
            (
                "m/0'/2147483647'/1'",
                bytes.fromhex('fcadf38c'),
                bytes.fromhex('73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90'),
                bytes.fromhex('3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c'),
                bytes.fromhex('002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45'),
            ),
            (
                "m/0'/2147483647'/1'/2147483646'",
                bytes.fromhex('aca70953'),
                bytes.fromhex('0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a'),
                bytes.fromhex('5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72'),
                bytes.fromhex('00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b'),
            ),
            (
                "m/0'/2147483647'/1'/2147483646'/2'",
                bytes.fromhex('422c654b'),
                bytes.fromhex('5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4'),
                bytes.fromhex('551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d'),
                bytes.fromhex('0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0'),
            ),
        ),
    },
    {
        'curve': 'nist256p1',
        'seed': bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
        'keys': (
            (
                "m",
                bytes.fromhex('00000000'),
                bytes.fromhex('beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea'),
                bytes.fromhex('612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2'),
                bytes.fromhex('0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8'),
            ),
            (
                "m/28578'",
                bytes.fromhex('be6105b5'),
                bytes.fromhex('e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2'),
                bytes.fromhex('06f0db126f023755d0b8d86d4591718a5210dd8d024e3e14b6159d63f53aa669'),
                bytes.fromhex('02519b5554a4872e8c9c1c847115363051ec43e93400e030ba3c36b52a3e70a5b7'),
            ),
            (
                "m/28578'/33941",
                bytes.fromhex('3e2b7bc6'),
                bytes.fromhex('9e87fe95031f14736774cd82f25fd885065cb7c358c1edf813c72af535e83071'),
                bytes.fromhex('092154eed4af83e078ff9b84322015aefe5769e31270f62c3f66c33888335f3a'),
                bytes.fromhex('0235bfee614c0d5b2cae260000bb1d0d84b270099ad790022c1ae0b2e782efe120'),
            ),
        ),
    },
    {
        'curve': 'nist256p1',
        'seed': bytes.fromhex('a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446'),
        'keys': (
            (
                "m",
                bytes.fromhex('00000000'),
                bytes.fromhex('7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c'),
                bytes.fromhex('3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f'),
                bytes.fromhex('0383619fadcde31063d8c5cb00dbfe1713f3e6fa169d8541a798752a1c1ca0cb20'),
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
        # Python 3.5 introduced bytes.hex() instead of binascii.hexlify(), but this code works with Python 3.4 too.
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

    # Run test vectors from https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vectors
    for test_vector in SLIP0010_TEST_VECTORS:
        curve = test_vector['curve']
        seed = test_vector['seed']
        print("Testing SLIP-0010 test vector {}:{}".format(curve, binascii.hexlify(seed).decode('ascii')))
        for derivation_path, exp_fingerprint, exp_chaincode, exp_private, exp_public in test_vector['keys']:
            key, chaincode = bip32derive(derivation_path, seed, curve=curve)
            assert exp_chaincode == chaincode
            assert exp_private == key

            if derivation_path == 'm':
                assert exp_fingerprint == b'\x00\x00\x00\x00'

            curve_obj = KNOWN_CURVES[curve][0]
            pubkey_bytes = public_key(key, curve=curve)
            assert exp_public == pubkey_bytes
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

    # Test mnemonics with 12 words, from Twitter challenge:
    # * Subject (2020-05-28): https://twitter.com/alistairmilne/status/1266037520715915267
    # * Answer (2020-06-17): https://twitter.com/ThisIsMOLAANAA/status/1273144733641199617
    mnemonics = 'army excuse hero wolf disease liberty moral diagram treat stove message job'
    seed = bip39toseed(mnemonics)
    bitcoin_privkey = bip32derive("m/49'/0'/0'/0/0", seed)[0]
    bitcoin_pubkey = SECP256K1.public_point(bitcoin_privkey)
    p2sh_bytes = b'\x05' + bitcoin_pubkey.bitcoin_p2sh_p2wpkh()
    p2sh_bytes_checksum = hashlib.sha256(hashlib.sha256(p2sh_bytes).digest()).digest()[:4]
    assert base58_decode('3HX5tttedDehKWTTGpxaPAbo157fnjn89s', 0x19) == p2sh_bytes + p2sh_bytes_checksum
