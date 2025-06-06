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
import base64
import hashlib
import hmac
import itertools
import os.path
import unicodedata

from typing import Any, Iterable, Sequence  # noqa: F401

from ec_tests import ECPoint  # noqa: F401
from ec_tests import SECP256K1, SECP256R1, StandardCurve, decode_bigint_be, has_cryptodome_ripemd160
from ed25519_tests import Ed25519, Ed25519Point
from eth_functions_keccak import keccak256


ED25519 = Ed25519()


# Curves defined in https://github.com/satoshilabs/slips/blob/master/slip-0010.md
KNOWN_CURVES = {
    'bitcoin': (SECP256K1, b'Bitcoin seed'),
    'ed25519': (ED25519, b'ed25519 seed'),
    'nist p-256': (SECP256R1, b'Nist256p1 seed'),
    'nist256p1': (SECP256R1, b'Nist256p1 seed'),
    'secp256k1': (SECP256K1, b'Bitcoin seed'),
    'secp256r1': (SECP256R1, b'Nist256p1 seed'),
}  # type: dict[str, tuple[StandardCurve | Ed25519, bytes]]


def bip32derive_priv_int(
    privkey, chaincode, child_index, curve="secp256k1"
):  # type: (bytes, bytes, int, str) -> tuple[bytes, bytes]
    """Derive a key from a seed according to a BIP-0032 derivation path as integer"""
    try:
        curve_obj, _ = KNOWN_CURVES[curve.lower()]
    except KeyError:
        raise ValueError("Unknown curve name {}".format(repr(curve)))

    assert len(privkey) == 32
    assert len(chaincode) == 32
    kpar = int.from_bytes(privkey, 'big')
    cpar = chaincode

    assert 0 <= child_index <= 0xffffffff
    index_bytes = child_index.to_bytes(4, 'big')
    if child_index & 0x80000000:
        data = b'\x00' + kpar.to_bytes(32, 'big') + index_bytes
    else:
        if curve_obj == ED25519:
            raise ValueError("Ed25519 derivation does not support non-hardened key")
        assert isinstance(curve_obj, StandardCurve)
        assert curve_obj.g.order is not None
        pubkey = curve_obj.g * kpar
        assert pubkey.x is not None
        assert pubkey.y is not None
        data = (b'\x03' if pubkey.y & 1 else b'\x02') + pubkey.x.to_bytes(32, 'big') + index_bytes

    while True:
        child_i = hmac.new(cpar, data, 'sha512').digest()
        if curve_obj == ED25519:
            kpar = int.from_bytes(child_i[:32], 'big')
        else:
            assert isinstance(curve_obj, StandardCurve)
            assert curve_obj.g.order is not None
            int_ileft = int.from_bytes(child_i[:32], 'big')
            kpar_new = (kpar + int_ileft) % curve_obj.g.order
            if int_ileft >= curve_obj.g.order or kpar_new == 0:
                # resulting key is invalid, loop
                # This is in fact SLIP-0010 rejection algorithm
                data = b'\x01' + child_i[32:] + index_bytes
                continue
            kpar = kpar_new
        break

    return kpar.to_bytes(32, 'big'), child_i[32:]


def bip32derive(derivation_path, seed, curve='secp256k1'):  # type: (str, bytes, str) -> tuple[bytes, bytes]
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
        if curve_obj != ED25519:
            assert isinstance(curve_obj, StandardCurve)
            assert curve_obj.g.order is not None
            if kpar == 0 or kpar >= curve_obj.g.order:
                seed = master_key
                continue
        break

    kpar_bytes = master_key[:32]
    for child in parts[1:]:
        if child.endswith("'"):
            index = 0x80000000 + int(child[:-1])
        else:
            index = int(child)
        kpar_bytes, cpar = bip32derive_priv_int(kpar_bytes, cpar, index, curve=curve)

    return kpar_bytes, cpar


def bip39toseed(sentence, passphrase=None):  # type: (str, str | None) -> bytes
    """Compute the deterministic key (seed) associated with a sentence of BIP-0039 mnemonics"""
    sentence = unicodedata.normalize('NFKD', sentence)
    salt = b'mnemonic'
    if passphrase:
        passphrase = unicodedata.normalize('NFKD', passphrase)
        salt += passphrase.encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', sentence.encode('utf-8'), salt, 2048, 64)


def load_bip39_wordlist(lang):  # type: (str) -> tuple[str, ...]
    """Load a list of words for the specified language

    Dictionaries are available on:
    https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md
    """
    file_path = os.path.join(os.path.dirname(__file__), "bip39_{}.txt".format(lang))
    with open(file_path, "r") as words_fd:
        words = tuple(line.strip() for line in words_fd)
    assert len(words) == 2048
    return words


BIP39_ENGLISH = load_bip39_wordlist("english")  # type: tuple[str, ...]


def bip39_entropy2mnemonics(entropy, wordlist=BIP39_ENGLISH):  # type: (bytes, Sequence[str]) -> str
    """Convert some bytes to a BIP-0039 mnemonic sentence"""
    assert len(entropy) in {16, 20, 24, 28, 32}  # Entropy of 128, 160, 192, 224 or 256 bits
    checksum_size_bits = len(entropy) // 4  # In BIP-0039: CS = ENT / 32
    checksum_size_bytes, checksum_size_rem = divmod(checksum_size_bits, 8)
    checksum_full = hashlib.sha256(entropy).digest()
    if checksum_size_rem == 0:
        checksum = int.from_bytes(checksum_full[:checksum_size_bytes], "big")
    else:
        checksum = int.from_bytes(checksum_full[:checksum_size_bytes + 1], "big") >> (8 - checksum_size_rem)

    assert checksum.bit_length() <= checksum_size_bits

    num_words = (len(entropy) * 8 + checksum_size_bits) // 11  # In BIP-0039: MS = (ENT + CS) / 11
    entropy_int = (int.from_bytes(entropy, "big") << checksum_size_bits) | checksum
    words = []
    for idx in range(num_words - 1, -1, -1):
        word_index = (entropy_int >> (11 * idx)) & 0x7ff
        words.append(wordlist[word_index])
    return " ".join(words)


def bip39_mnemonics2entropy(
    mnemonics, verify_checksum=True, wordlist=BIP39_ENGLISH
):  # type: (str, bool, Sequence[str]) -> bytes
    """Convert a BIP-0039 mnemonic sentence to the underlying entropy"""
    words = mnemonics.split()
    assert len(words) in {12, 15, 18, 21, 24}
    checksum_size_bits = len(words) // 3
    entropy_len = checksum_size_bits * 4
    entropy_int = 0
    for word in words:
        word_index = wordlist.index(word)
        entropy_int = (entropy_int << 11) | word_index

    entropy = (entropy_int >> checksum_size_bits).to_bytes(entropy_len, "big")
    if not verify_checksum:
        return entropy
    checksum_int = entropy_int & ((1 << checksum_size_bits) - 1)
    checksum_size_bytes, checksum_size_rem = divmod(checksum_size_bits, 8)
    checksum_full = hashlib.sha256(entropy).digest()
    if checksum_size_rem == 0:
        checksum = int.from_bytes(checksum_full[:checksum_size_bytes], "big")
    else:
        checksum = int.from_bytes(checksum_full[:checksum_size_bytes + 1], "big") >> (8 - checksum_size_rem)
    if checksum != checksum_int:
        raise ValueError(f"Invalid checksum: {checksum} != {checksum_int}")
    return entropy


def public_point(private_key, curve='secp256k1'):  # type: (bytes, str) -> ECPoint | Ed25519Point
    """Retrieve the public key as a point object"""
    try:
        curve_obj = KNOWN_CURVES[curve.lower()][0]
    except KeyError:
        raise ValueError(f"Unknown curve name {curve!r}")
    return curve_obj.public_point(private_key)


def public_key(private_key, curve='secp256k1'):  # type: (bytes, str) -> bytes
    """Retrieve the public key as bytes"""
    try:
        curve_obj = KNOWN_CURVES[curve.lower()][0]
    except KeyError:
        raise ValueError(f"Unknown curve name {curve!r}")
    pubkey = curve_obj.public_point(private_key)
    if curve_obj == ED25519:
        assert isinstance(curve_obj, Ed25519)
        assert isinstance(pubkey, Ed25519Point)
        encoded = pubkey.encode()
        assert encoded == curve_obj.public_key(private_key)
        return b'\x00' + encoded
    assert pubkey.x is not None
    assert pubkey.y is not None
    return (b'\x03' if pubkey.y & 1 else b'\x02') + pubkey.x.to_bytes(32, 'big')


BASE58_BITCOIN_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
assert len(BASE58_BITCOIN_ALPHABET) == 58


def base58_decode(data, size=None):  # type: (str, int | None) -> bytes
    """Decode some data encoded using Base58 bitcoin alphabet"""
    value = 0
    leading_zeros = 0
    for char in data:
        value = value * 58 + BASE58_BITCOIN_ALPHABET.index(char)
        if value == 0:
            leading_zeros += 1
    if size is None:
        size = leading_zeros + (value.bit_length() + 7) // 8
    return value.to_bytes(size, 'big')


def base58_encode(data):  # type: (bytes) -> str
    """Encode some data using Base58 bitcoin alphabet"""
    value = int.from_bytes(data, 'big')
    result = []
    while value:
        value, rem = divmod(value, 58)
        result.append(BASE58_BITCOIN_ALPHABET[rem])
    # Add leading zeros
    for by in data:
        if by != 0:
            break
        result.append('1')
    return "".join(result[::-1])


def btc_wallet_addr_p2pkh(public_key):  # type: (ECPoint) -> str
    """Compute the Bitcoin Pay-to-Public-Key-Hash (P2PKH) address from a public key

    This is one of the first ways of computing a Bitcoin address from a public key.
    The address begins with 1 and contains between 26 and 34 characters:
    https://bitcoin.stackexchange.com/questions/36944/what-are-the-minimum-and-maximum-lengths-of-a-mainnet-bitcoin-address/36948
    """
    # Version byte 0
    p2pkh_bytes = b"\x00" + public_key.bitcoin_hash160()
    p2pkh_bytes_checksum = hashlib.sha256(hashlib.sha256(p2pkh_bytes).digest()).digest()[:4]
    return base58_encode(p2pkh_bytes + p2pkh_bytes_checksum)


def btc_wallet_addr_p2sh(public_key):  # type: (ECPoint) -> str
    """Compute the Bitcoin Pay-to-Script-Hash (P2SH) address from a public key

    A Pay to Witness Public Key Hash (P2WPKH) script is:

        OP_0 0x14 <PubKey Hash>

    A Pay to Script Hash is the RIPEMD160 of SHA256 of this script, prefixed
    by 05 and encoded in base58.
    """
    p2sh_bytes = b'\x05' + public_key.bitcoin_p2sh_p2wpkh()
    p2sh_bytes_checksum = hashlib.sha256(hashlib.sha256(p2sh_bytes).digest()).digest()[:4]
    return base58_encode(p2sh_bytes + p2sh_bytes_checksum)


BECH32_BITCOIN_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
assert len(BECH32_BITCOIN_ALPHABET) == 32
BECH32_GEN = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)


def bech32_polymod(values):  # type: (Iterable[int]) -> int
    """Function from https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki"""
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= BECH32_GEN[i]
    return chk


def bech32_hrp_expand(s):  # type: (str) -> list[int]
    """Expand the human-readable part for the Bech32 checksum computation

    Function from https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    """
    return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]


def bech32_encode(hrp, data):  # type: (str, bytes) -> str
    """Encode some data using Bech32 bitcoin encoding, with a human-readable part

    https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    "Base32 address format for native v0-16 witness outputs"

    Reference implementation:
    https://github.com/sipa/bech32/blob/7a7d7ab158db7078a333384e0e918c90dbc42917/ref/python/segwit_addr.py
    """
    # Convert data to 5-bit numbers
    acc = 0
    bits = 0
    data_5bits = []  # type: list[int]
    for value in data:
        assert 0 <= value <= 0xFF
        acc = (acc << 8) | value
        bits += 8
        while bits >= 5:
            bits -= 5
            data_5bits.append((acc >> bits) & 0x1F)
        acc &= (1 << bits) - 1
    if bits:
        # Add padding
        data_5bits.append((acc << (5 - bits)) & 0x1F)

    if hrp in {"bc", "tb"}:
        # Special treatment for Bitcoin addresses: insert the witness version 0
        data_5bits.insert(0, 0)
    polymod = bech32_polymod(itertools.chain(bech32_hrp_expand(hrp), data_5bits, [0, 0, 0, 0, 0, 0]))
    polymod ^= 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + '1' + ''.join(BECH32_BITCOIN_ALPHABET[d] for d in itertools.chain(data_5bits, checksum))


def bech32_decode(bech, expected_hrp=None):  # type: (str, str | None) -> bytes
    """Decode some data using Bech32 bitcoin encoding

    This is voluntary less strict than the reference implementation
    https://github.com/sipa/bech32/blob/7a7d7ab158db7078a333384e0e918c90dbc42917/ref/python/segwit_addr.py
    """
    bech = bech.lower()
    # Find the separator
    hrp, encoded_data = bech.rsplit('1', 1)
    if expected_hrp is not None and hrp != expected_hrp:
        raise ValueError(f"Unexpected human-readable part {hrp!r} != {expected_hrp!r}")
    data = [BECH32_BITCOIN_ALPHABET.index(x) for x in encoded_data]
    checksum = bech32_polymod(bech32_hrp_expand(hrp) + data)
    if checksum != 1:
        raise ValueError(f"Invalid checksum in Bech32 {bech!r}: {checksum!r}")
    if hrp in {"bc", "tb"}:
        # Special treatment for Bitcoin addresses
        if data[0] != 0:
            raise ValueError(f"Invalid version in Bech32 data {data!r}")
        data = data[1:]

    # Remove the checksum from the data and convert the 5-bit numbers to octets
    acc = 0
    bits = 0
    decoded = []  # type: list[int]
    for value in data[:-6]:
        assert 0 <= value <= 0x1F
        acc = (acc << 5) | value
        bits += 5
        while bits >= 8:
            bits -= 8
            decoded.append((acc >> bits) & 0xFF)
        acc &= (1 << bits) - 1
    if bits >= 5 or acc:
        raise ValueError(f"Unexpected passing from base32 data: bits={bits}, acc={acc}")
    return bytes(decoded)


def eth_wallet_addr(public_key, chain_id=None):  # type: (ECPoint, int | None) -> str
    """Compute the Ethereum address from a public key"""
    assert public_key.x is not None
    assert public_key.y is not None
    hex_addr = keccak256(public_key.x.to_bytes(32, 'big') + public_key.y.to_bytes(32, 'big'))[-20:].hex()
    addr_for_checksum = (str(chain_id) + '0x' + hex_addr) if chain_id is not None else hex_addr
    checksum = keccak256(addr_for_checksum.encode('ascii'))[:20].hex()
    return '0x' + ''.join(
        hex_addr_char if ck_char in "01234567" else hex_addr_char.upper()
        for hex_addr_char, ck_char in zip(hex_addr, checksum)
    )


class SolanaBadSeedError(Exception):
    pass


def solana_create_program_address(seed, program_id):  # type: (bytes, bytes) -> bytes
    """Derive a Solana Program Derived Address (PDA) with the given full seed

    In the official implementation, seed is a vector of at most 16 chunks of at most 32 bytes:
    https://github.com/anza-xyz/solana-sdk/blob/pubkey%40v2.3.0/pubkey/src/lib.rs#L913-L920

    Documentation: https://solana.com/docs/core/pda
    """
    pda = hashlib.sha256(seed + program_id + b"ProgramDerivedAddress").digest()
    if Ed25519Point.is_ycomp_on_curve(pda):
        raise SolanaBadSeedError()
    return pda


def solana_find_program_address(seed, program_id):  # type: (bytes, bytes) -> tuple[bytes, int]
    """Derive a Solana Program Derived Address (PDA) with the given seed, bumping it

    Documentation: https://solana.com/docs/core/pda
    """
    for bump in range(255, -1, -1):
        try:
            pda = solana_create_program_address(seed + bump.to_bytes(1, "big"), program_id)
            return pda, bump
        except SolanaBadSeedError:
            pass
    raise SolanaBadSeedError()  # Should never happen


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
)  # type: tuple[dict[str, Any], ...]


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
)  # type: tuple[dict[str, Any], ...]


if __name__ == '__main__':
    assert base58_encode(b"\0\0\0") == "111"
    assert base58_decode("111") == b"\0\0\0"

    BECH32_TEST_VECTORS = (
        # Test vectors from
        # https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
        # and https://github.com/iqlusioninc/crates/blob/subtle-encoding/v0.5.1/subtle-encoding/src/bech32.rs
        ("a", "A12UEL5L", ""),
        ("a", "a12uel5l", ""),
        (
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "",
        ),
        ("abcdef", "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", "00443214c74254b635cf84653a56d7c675be77df"),
        (
            "1",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "split",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            "c5f38b70305f519bf66d85fb6cf03058f3dde463ecd7918f2dc743918f2d",
        ),
        ("?", "?1ezyfcl", ""),
        # https://github.com/sipa/bech32/blob/7a7d7ab158db7078a333384e0e918c90dbc42917/ref/python/tests.py#L88-L102
        ("bc", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "751e76e8199196d454941c45d1b3a323f1433bd6"),
        ("tb", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "751e76e8199196d454941c45d1b3a323f1433bd6"),
        (
            "bc",
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
            "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        ),
        (
            "tb",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        ),
        (
            "tb",
            "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
            "000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
        ),
        # https://stackoverflow.com/questions/70981681/how-to-generate-hd-wallet-keys-addresses-given-seed-phrase-with-cosmos-sdk
        # ("04" and public key)
        # https://github.com/cosmos/cosmos-sdk/blob/main/docs/architecture/adr-028-public-key-addresses.md
        # Encoding:
        # https://github.com/cometbft/cometbft/blob/4226b0ea6ab4725ef807a16b86d6d24835bb45d4/spec/core/encoding.md
        (
            "atom",
            "atom1qspau72rtj7g57v7lsjvmnna8vvqlvq56hcejj0m34sau0eph8mvr7qgl9avu",
            "0403de79435cbc8a799efc24cdce7d3b180fb014d5f19949fb8d61de3f21b9f6c1f8",
        ),
        # https://github.com/ChorusOne/cosmos-bech32-convertor/blob/ab9886f2580cb85b40ed06db45c07d0f1e38afa7/README.md
        (
            "cosmosaccpub",
            "cosmosaccpub1addwnpepqg5ec06deee7rk3s0xmwn0f3e66wv65l2xc07ynxzj67z9ld5dcwv6ljvv9",
            "eb5ae9872102299c3f4dce73e1da3079b6e9bd31ceb4e66a9f51b0ff126614b5e117eda370e6",
        ),
        (
            "cosmospub",
            "cosmospub1addwnpepqg5ec06deee7rk3s0xmwn0f3e66wv65l2xc07ynxzj67z9ld5dcwvwgyrcu",
            "eb5ae9872102299c3f4dce73e1da3079b6e9bd31ceb4e66a9f51b0ff126614b5e117eda370e6",
        ),
        # https://github.com/nymtech/nym/blob/v1.1.22/envs/mainnet.env
        (
            "n",
            "n17srjznxl9dvzdkpwpw24gg668wc73val88a6m5ajg6ankwvz9wtst0cznr",
            "f407214cdf2b5826d82e0b9554235a3bb1e8b3bf39fbadd3b246bb3b39822b97",
        ),
        (
            "n",
            "n1nc5tatafv6eyq7llkr2gv50ff9e22mnf70qgjlv737ktmt4eswrq73f2nw",
            "9e28beafa966b2407bffb0d48651e94972a56e69f3c0897d9e8facbdaeb98386",
        ),
        (
            "n",
            "n19lc9u84cz0yz3fww5283nucc9yvr8gsjmgeul0",
            "2ff05e1eb813c828a5cea28f19f318291833a212",
        ),
        (
            "n",
            "n1rw8fw2mpcpzzq3jpa4e52ufawnmj5a4u68p35umvgskewuw0nlzsaa5w4m",
            "1b8e972b61c044204641ed7345713d74f72a76bcd1c31a736c442d9771cf9fc5",
        ),
        (
            "n",
            "n10yyd98e2tuwu0f7ypz9dy3hhjw7v772q6287gy",
            "7908d29f2a5f1dc7a7c4088ad246f793bccf7940",
        ),
        # https://github.com/confio/cosmos-hd-key-derivation-spec/blob/76f9ec9e34dfab2a6dda71aff334a03d9e2a3121/README.md#reuse-of-the-cosmos-hub-path-in-cosmos
        (
            "achain",
            "achain1pkptre7fdkl6gfrzlesjjvhxhlc3r4gmjufvfw",
            "0d82b1e7c96dbfa42462fe612932e6bff111d51b",
        ),
        (
            "bitwhatever",
            "bitwhatever1pkptre7fdkl6gfrzlesjjvhxhlc3r4gmtwnu3c",
            "0d82b1e7c96dbfa42462fe612932e6bff111d51b",
        ),
    )
    for test_hrp, test_bech32, test_hex in BECH32_TEST_VECTORS:
        test_raw = bytes.fromhex(test_hex)
        test_decoded = bech32_decode(test_bech32, expected_hrp=test_hrp)
        assert test_decoded == test_raw, f"Unexpected Bech32 {test_decoded.hex()} from {test_bech32}"
        test_encoded = bech32_encode(test_hrp, test_raw)
        assert test_encoded == test_bech32.lower()

    # Cosmos derivation from
    # https://github.com/confio/cosmos-hd-key-derivation-spec/blob/76f9ec9e34dfab2a6dda71aff334a03d9e2a3121/README.md#reuse-of-the-cosmos-hub-path-in-cosmos
    if has_cryptodome_ripemd160:
        import Cryptodome.Hash.RIPEMD160

        pubkey_bytes = base64.b64decode("A08EGB7ro1ORuFhjOnZcSgwYlpe0DSFjVNUIkNNQxwKQ")
        assert Cryptodome.Hash.RIPEMD160.new(hashlib.sha256(pubkey_bytes).digest()).digest() == bytes.fromhex(
            "0d82b1e7c96dbfa42462fe612932e6bff111d51b"
        )
        assert pubkey_bytes[0] == 3
        assert len(pubkey_bytes) == 33
        pubkey = SECP256K1.pt_from_x(decode_bigint_be(pubkey_bytes[1:]), is_odd=True)
        assert pubkey.bitcoin_hash160() == bytes.fromhex("0d82b1e7c96dbfa42462fe612932e6bff111d51b")

    # Run test vectors from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
    for test_vector in BIP32_TEST_VECTORS:
        seed = test_vector['seed']  # type: bytes
        print(f"Testing BIP32 test vector {seed.hex()}")
        for derivation_path, expected_pub, expected_priv in test_vector['keys']:
            key, chaincode = bip32derive(derivation_path, seed)

            pubkey = SECP256K1.g * int.from_bytes(key, 'big')
            assert pubkey.x is not None
            assert pubkey.y is not None
            pubkey_bytes = (b'\x03' if pubkey.y & 1 else b'\x02') + pubkey.x.to_bytes(32, 'big')

            # Key encoding
            decoded_pub = base58_decode(expected_pub, 0x52)
            decoded_priv = base58_decode(expected_priv, 0x52)
            assert base58_encode(decoded_pub) == expected_pub
            assert base58_encode(decoded_priv) == expected_priv
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

            print(f"- {derivation_path}: OK")

    # Run test vectors from https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vectors
    for test_vector in SLIP0010_TEST_VECTORS:
        curve = test_vector['curve']  # type: str
        seed = test_vector['seed']
        print(f"Testing SLIP-0010 test vector {curve}:{seed.hex()}")
        for derivation_path, exp_fingerprint, exp_chaincode, exp_private, exp_public in test_vector['keys']:
            key, chaincode = bip32derive(derivation_path, seed, curve=curve)
            assert exp_chaincode == chaincode
            assert exp_private == key

            if derivation_path == 'm':
                assert exp_fingerprint == b'\x00\x00\x00\x00'

            curve_obj = KNOWN_CURVES[curve][0]
            pubkey_bytes = public_key(key, curve=curve)
            assert exp_public == pubkey_bytes
            print(f"- {derivation_path}: OK")

    # Test mnemonics with 12 words from
    # https://github.com/trezor/python-mnemonic/blob/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/vectors.json
    mnemonics = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    assert bip39_entropy2mnemonics(b"\0" * 16) == mnemonics
    assert b"\0" * 16 == bip39_mnemonics2entropy(mnemonics)
    seed = bip39toseed(mnemonics)
    assert seed == bytes.fromhex(
        '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1' +
        '9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4')

    mnemonics = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art'  # noqa
    assert bip39_entropy2mnemonics(b"\0" * 32) == mnemonics
    assert b"\0" * 32 == bip39_mnemonics2entropy(mnemonics)

    # Test to derive Monero seed
    secret, chaincode = bip32derive("m/44'/128'/0'/0/0", seed)
    assert secret == bytes.fromhex('db9e57474be8b64118b6acf6ecebd13f8f7c326b3bc1b19f4546573d6bac9dcf')

    # Test mnemonics with 12 words, from Twitter challenge:
    # * Subject (2020-05-28): https://twitter.com/alistairmilne/status/1266037520715915267
    # * Answer (2020-06-17): https://twitter.com/ThisIsMOLAANAA/status/1273144733641199617
    mnemonics = 'army excuse hero wolf disease liberty moral diagram treat stove message job'
    assert bip39_entropy2mnemonics(bytes.fromhex("0c09e1ad7e63f101e3e9e7e7dad62fbc")) == mnemonics
    assert bytes.fromhex("0c09e1ad7e63f101e3e9e7e7dad62fbc") == bip39_mnemonics2entropy(mnemonics)
    seed = bip39toseed(mnemonics)
    bitcoin_privkey = bip32derive("m/49'/0'/0'/0/0", seed)[0]
    bitcoin_pubkey = SECP256K1.public_point(bitcoin_privkey)
    p2sh_bytes = b'\x05' + bitcoin_pubkey.bitcoin_p2sh_p2wpkh()
    p2sh_bytes_checksum = hashlib.sha256(hashlib.sha256(p2sh_bytes).digest()).digest()[:4]
    assert base58_decode('3HX5tttedDehKWTTGpxaPAbo157fnjn89s') == p2sh_bytes + p2sh_bytes_checksum
    assert base58_decode('3HX5tttedDehKWTTGpxaPAbo157fnjn89s', 0x19) == p2sh_bytes + p2sh_bytes_checksum
    assert '3HX5tttedDehKWTTGpxaPAbo157fnjn89s' == base58_encode(p2sh_bytes + p2sh_bytes_checksum)
    assert '3HX5tttedDehKWTTGpxaPAbo157fnjn89s' == btc_wallet_addr_p2sh(bitcoin_pubkey)

    # Old encoding
    p2pkh_bytes = b'\x00' + bitcoin_pubkey.bitcoin_hash160()
    p2pkh_bytes_checksum = hashlib.sha256(hashlib.sha256(p2pkh_bytes).digest()).digest()[:4]
    assert base58_decode('1F2C2dfD8B5qLM7ZrW4Ag1kLUg8sZjfyBB') == p2pkh_bytes + p2pkh_bytes_checksum
    assert base58_decode('1F2C2dfD8B5qLM7ZrW4Ag1kLUg8sZjfyBB', 0x19) == p2pkh_bytes + p2pkh_bytes_checksum
    assert '1F2C2dfD8B5qLM7ZrW4Ag1kLUg8sZjfyBB' == base58_encode(p2pkh_bytes + p2pkh_bytes_checksum)
    assert '1F2C2dfD8B5qLM7ZrW4Ag1kLUg8sZjfyBB' == btc_wallet_addr_p2pkh(bitcoin_pubkey)

    # Test Bitcoin and Ethereum derivation from the 12-word zero mnemonics, with https://app.devicesdk.ledger.com/
    mnemonics = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    seed = bip39toseed(mnemonics)
    # Bitcoin Nested Segwit
    bitcoin_privkey = bip32derive("m/49'/0'/0'/0/0", seed)[0]
    bitcoin_pubkey = SECP256K1.public_point(bitcoin_privkey)
    assert '37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf' == btc_wallet_addr_p2sh(bitcoin_pubkey)
    # Bitcoin Native Segwit
    bitcoin_privkey = bip32derive("m/84'/0'/0'/0/0", seed)[0]
    bitcoin_pubkey = SECP256K1.public_point(bitcoin_privkey)
    assert 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu' == bech32_encode("bc", bitcoin_pubkey.bitcoin_hash160())
    # Ethereum
    eth_privkey = bip32derive("m/44'/60'/0'/0/0", seed)[0]
    eth_pubkey = SECP256K1.public_point(eth_privkey)
    assert '0x9858EfFD232B4033E47d90003D41EC34EcaEda94' == eth_wallet_addr(eth_pubkey)
    # Solana
    solana_privkey = bip32derive("m/44'/501'/0'/0'", seed, curve="ed25519")[0]
    solana_pubkey = ED25519.public_key(solana_privkey)
    assert 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk' == base58_encode(solana_pubkey)

    # Test mnemonic phrase used by Hardhat: https://hardhat.org/hardhat-network/docs/reference#accounts
    mnemonics = 'test test test test test test test test test test test junk'
    assert bip39_entropy2mnemonics(bytes.fromhex("df9bf37e6fcdf9bf37e6fcdf9bf37e3c")) == mnemonics
    assert bytes.fromhex("df9bf37e6fcdf9bf37e6fcdf9bf37e3c") == bip39_mnemonics2entropy(mnemonics)
    hardhat_20_privkeys = (
        bytes.fromhex('ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'),
        bytes.fromhex('59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'),
        bytes.fromhex('5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a'),
        bytes.fromhex('7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6'),
        bytes.fromhex('47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a'),
        bytes.fromhex('8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba'),
        bytes.fromhex('92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e'),
        bytes.fromhex('4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356'),
        bytes.fromhex('dbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97'),
        bytes.fromhex('2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6'),
        bytes.fromhex('f214f2b2cd398c806f84e317254e0f0b801d0643303237d97a22a48e01628897'),
        bytes.fromhex('701b615bbdfb9de65240bc28bd21bbc0d996645a3dd57e7b12bc2bdf6f192c82'),
        bytes.fromhex('a267530f49f8280200edf313ee7af6b827f2a8bce2897751d06a843f644967b1'),
        bytes.fromhex('47c99abed3324a2707c28affff1267e45918ec8c3f20b8aa892e8b065d2942dd'),
        bytes.fromhex('c526ee95bf44d8fc405a158bb884d9d1238d99f0612e9f33d006bb0789009aaa'),
        bytes.fromhex('8166f546bab6da521a8369cab06c5d2b9e46670292d85c875ee9ec20e84ffb61'),
        bytes.fromhex('ea6c44ac03bff858b476bba40716402b03e41b8e97e276d1baec7c37d42484a0'),
        bytes.fromhex('689af8efa8c651a91ad287602527f3af2fe9f6501a7ac4b061667b5a93e037fd'),
        bytes.fromhex('de9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0'),
        bytes.fromhex('df57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e'),
    )
    hardhat_20_addresses = (
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
        "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
        "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
        "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
        "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
        "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955",
        "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
        "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
        "0xBcd4042DE499D14e55001CcbB24a551F3b954096",
        "0x71bE63f3384f5fb98995898A86B02Fb2426c5788",
        "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a",
        "0x1CBd3b2770909D4e10f157cABC84C7264073C9Ec",
        "0xdF3e18d64BC6A983f673Ab319CCaE4f1a57C7097",
        "0xcd3B766CCDd6AE721141F452C550Ca635964ce71",
        "0x2546BcD3c84621e976D8185a91A922aE77ECEc30",
        "0xbDA5747bFD65F08deb54cb465eB87D40e51B197E",
        "0xdD2FD4581271e230360230F9337D5c0430Bf44C0",
        "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199",
    )
    seed = bip39toseed(mnemonics)
    print(f"Testing Hardhat seed {seed.hex()}")
    for idx in range(20):
        eth_privkey = bip32derive(f"m/44'/60'/0'/0/{idx}", seed)[0]
        assert eth_privkey == hardhat_20_privkeys[idx]
        eth_addr = eth_wallet_addr(SECP256K1.public_point(eth_privkey))
        print(f"- m/44'/60'/0'/0/{idx:<2d}: {eth_addr}")
        assert eth_addr == hardhat_20_addresses[idx]

    # Test Solana key encoding
    # https://github.com/gagliardetto/solana-go/blob/ca3f5f643435c1614475b2e564272bb8e6e21c1e/keys_test.go
    # https://github.com/gagliardetto/solana-go/blob/98efad3ab010f7aa6abeb78f24f87d3b5c2904c3/testdata/standard.solana-keygen.json
    print("Testing Solana keys and accounts encoding")
    solana_test_secret_key = bytes.fromhex(
        "feeba655701d84107e57ea3a9078628d4b85550a1f474a9351bd80b470156e3ed1ee412af80c981c822eaa2013080b1dffd0cf127b83e63cf99d4485f6bb2d3e"  # noqa: E501
    )
    solana_test_secret_key_b58 = "66cDvko73yAf8LYvFMM3r8vF5vJtkk7JKMgEKwkmBC86oHdq41C7i1a2vS3zE1yCcdLLk6VUatUb32ZzVjSBXtRs"  # noqa: E501
    solana_test_public_key_b58 = "F8UvVsKnzWyp2nF8aDcqvQ2GVcRpqT91WDsAtvBKCMt9"
    assert len(solana_test_secret_key) == 64
    assert base58_encode(solana_test_secret_key) == solana_test_secret_key_b58
    assert base58_decode(solana_test_secret_key_b58) == solana_test_secret_key

    # The secret key actual contains both the EC private key and the public key
    solana_test_public_key_point = ED25519.public_point(solana_test_secret_key[:32])
    solana_test_public_key_bytes = ED25519.public_key(solana_test_secret_key[:32])
    assert Ed25519Point.decode(solana_test_public_key_bytes) == solana_test_public_key_point
    assert len(solana_test_public_key_bytes) == 32
    assert solana_test_secret_key[32:] == solana_test_public_key_bytes
    assert base58_encode(solana_test_public_key_bytes) == solana_test_public_key_b58
    assert base58_decode(solana_test_public_key_b58) == solana_test_public_key_bytes

    # Test Solana Program Derived Address (PDA, https://solana.com/docs/core/pda)
    assert Ed25519Point.is_ycomp_on_curve(solana_test_public_key_bytes)
    # https://github.com/kevinheavey/solders/blob/0.26.0/docs/tutorials/pubkeys.rst#checking-if-an-address-has-a-private-key
    assert Ed25519Point.is_ycomp_on_curve(base58_decode("5oNDL3swdJJF1g9DzJiZ4ynHXgszjAEpUkxVYejchzrY"))
    assert not Ed25519Point.is_ycomp_on_curve(base58_decode("4BJXYkfvg37zEmBbsacZjeQDpTNx91KppxFJxRqrz48e"))

    pda, bump = solana_find_program_address(b"", base58_decode("11111111111111111111111111111111"))
    assert base58_encode(pda) == "Cu7NwqCXSmsR5vgGA3Vw9uYVViPi3kQvkbKByVQ8nPY9"
    assert bump == 255
    assert solana_create_program_address(b"\xff", base58_decode("11111111111111111111111111111111")) == pda

    pda, bump = solana_find_program_address(b"helloWorld", base58_decode("11111111111111111111111111111111"))
    assert base58_encode(pda) == "46GZzzetjCURsdFPb7rcnspbEMnCBXe9kpjrsZAkKb6X"
    assert bump == 254
    assert solana_create_program_address(b"helloWorld\xfe", base58_decode("11111111111111111111111111111111")) == pda

    # Solana token program https://explorer.solana.com/address/TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
    # and https://solscan.io/account/TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
    # Created by signature https://explorer.solana.com/tx/3zaRSFwWb8EhEfz5hdrLLepvAAUh2UDjitD3cb5FB1LXVdRoTFRthXzPb5UGremjLo4Un7yhLttzs7RxdVE4wdYm  # noqa: E501
    # (and the private key could be made public:
    # https://solana.stackexchange.com/questions/4027/after-deployment-of-a-program-can-the-program-ids-private-key-be-made-public)
    assert Ed25519Point.is_ycomp_on_curve(base58_decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"))
    # Example of token account from https://solana.com/docs/tokens
    # spl-token create-account --owner 2i3KvjDCZWxBsqcxBHpdEaZYQwQSYE6LXUMx5VjY5XrR 99zqUzQGohamfYxyo8ykTEbi91iom3CLmwCA75FK5zTg  # noqa: E501
    # => Creating account Hmyk3FSw4cfsuAes7sanp2oxSkE9ivaH6pMzDzbacqmt
    # https://explorer.solana.com/address/99zqUzQGohamfYxyo8ykTEbi91iom3CLmwCA75FK5zTg?cluster=devnet
    # https://explorer.solana.com/address/Hmyk3FSw4cfsuAes7sanp2oxSkE9ivaH6pMzDzbacqmt?cluster=devnet
    # https://explorer.solana.com/tx/44vqKdfzspT592REDPY4goaRJH3uJ3Ce13G4BCuUHg35dVUbHuGTHvqn4ZjYF9BGe9QrjMfe9GmuLkQhSZCBQuEt?cluster=devnet
    # logic from https://github.com/solana-program/associated-token-account/blob/9d94201e8158f06015ff80ad47fefac62a2ec450/program/src/lib.rs#L65  # noqa: E501
    wallet_address = base58_decode("2i3KvjDCZWxBsqcxBHpdEaZYQwQSYE6LXUMx5VjY5XrR")
    token_mint_address = base58_decode("99zqUzQGohamfYxyo8ykTEbi91iom3CLmwCA75FK5zTg")
    token_program_id = base58_decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
    associated_token_program_id = base58_decode("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
    my_token_account, bump = solana_find_program_address(
        wallet_address + token_program_id + token_mint_address,
        associated_token_program_id,
    )
    assert base58_encode(my_token_account) == "Hmyk3FSw4cfsuAes7sanp2oxSkE9ivaH6pMzDzbacqmt"
    assert bump == 251

    # Verify the transaction signature, from data obtained from Solana devnet API:
    # curl https://api.devnet.solana.com -X POST -H "Content-Type: application/json" -d
    #   '{"jsonrpc":"2.0", "id":1, "method":"getTransaction", "params":[
    #       "44vqKdfzspT592REDPY4goaRJH3uJ3Ce13G4BCuUHg35dVUbHuGTHvqn4ZjYF9BGe9QrjMfe9GmuLkQhSZCBQuEt",
    #       {"encoding": "base64"}]}'
    #   | jq '.result.transaction[0]'
    solana_tx_id = "44vqKdfzspT592REDPY4goaRJH3uJ3Ce13G4BCuUHg35dVUbHuGTHvqn4ZjYF9BGe9QrjMfe9GmuLkQhSZCBQuEt"
    solana_tx_signer_addr = "3z9vL1zjN6qyAFHhHQdWYRTFAcy69pJydkZmSFBKHg1R"
    solana_tx_bytes = base64.b64decode(
        "AZlwQM9W2Op/CCyn/lYAXcSwrytT5+iGK+/LuWZJ/RfFquiVyuLGjFzIyu1QebBKPAxedEGSZsDSfmr8jR4kyQ0BAA"
        "UHLFuQskIMiaj8Oy/WFaidHlRPWUnonjWPq4hkn1vbnHT5QLRxpBvSzC/hNa0VaaR9P9eKEuXi2YcQGLQsEsFJ8wAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABt324ddloZPZy+FGzut5rBy0he1fWzeROoz1hX7/AKkZXyFmpm"
        "cpze2ukmaRcxpDxtR7XfJoUU6wqxU2MJ9DOnkriYLB9Ko3bwzj/Kw+p5ETc/9yPenW3kzW7FfoR3yPjJclj04kifG7"
        "PRApFI4NgwtaE5na/xCEBI572Nvp+Fmor83yzqDb/bgHX6OQsThdSMC5WwmW+dTOf1tskfnz7QEGBgABBAUCAwEA"
    )
    assert len(solana_tx_bytes) == 336
    # Transaction format from hexdump:
    # (doc: https://solana.com/de/docs/core/transactions#transaction )
    # 01 : 1 signature
    #   997040cf56d8ea7f082ca7fe56005dc4b0af2b53e7e8862befcbb96649fd17c5
    #   aae895cae2c68c5cc8caed5079b04a3c0c5e74419266c0d27e6afc8d1e24c90d : signature (64 bytes)
    # 01 00 05 : message header (v0, 1 signer, 0 read-only signed accounts, 5 read-only unsigned accounts)
    # 07 : 7 account inputs
    #     (1 writable and signer)
    #   2c5b90b2420c89a8fc3b2fd615a89d1e544f5949e89e358fab88649f5bdb9c74 : 3z9vL1zjN6qyAFHhHQdWYRTFAcy69pJydkZmSFBKHg1R (source, fee payer)  # noqa: E501
    #     (0 read-only and signer)
    #     (1 writable and not signer)
    #   f940b471a41bd2cc2fe135ad1569a47d3fd78a12e5e2d9871018b42c12c149f3 : Hmyk3FSw4cfsuAes7sanp2oxSkE9ivaH6pMzDzbacqmt (created token account program)  # noqa: E501
    #     (5 read-only and not signer)
    #   0000000000000000000000000000000000000000000000000000000000000000 : 11111111111111111111111111111111 ("System Program")  # noqa: E501
    #   06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9 : TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA ("Token Program")  # noqa: E501
    #   195f2166a66729cdedae926691731a43c6d47b5df268514eb0ab1536309f433a : 2i3KvjDCZWxBsqcxBHpdEaZYQwQSYE6LXUMx5VjY5XrR (wallet)  # noqa: E501
    #   792b8982c1f4aa376f0ce3fcac3ea7911373ff723de9d6de4cd6ec57e8477c8f : 99zqUzQGohamfYxyo8ykTEbi91iom3CLmwCA75FK5zTg (token mint)  # noqa: E501
    #   8c97258f4e2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f859 : ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL ("Associated Token Program")  # noqa: E501
    # a8afcdf2cea0dbfdb8075fa390b1385d48c0b95b0996f9d4ce7f5b6c91f9f3ed : Recent Blockhash, CMUyavo32gpCn9ii7qxM4QrU42kXWQRo2tEYoK6p6RrU  # noqa: E501
    # 01 : 1 instruction
    #   06 : program ID index 6 ("Associated Token Program")
    #   06 : 6 accounts to pass
    #     00 01 04 05 02 03
    #   01 : program input data (1 bytes)
    #     00 : instruction 0 ("Create")
    solana_tx_signature = base58_decode(solana_tx_id)
    assert len(solana_tx_signature) == 64
    assert solana_tx_bytes[1:65] == solana_tx_signature
    solana_tx_signer_pubkey = base58_decode(solana_tx_signer_addr)
    ED25519.check_signature(solana_tx_bytes[65:], solana_tx_signature, solana_tx_signer_pubkey)

    # Also use pyca/cryptography library
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        print("Skipping test with pyca/cryptography")
    else:
        print("Verifying Solana transaction with pyca/cryptography")
        solana_tx_signer_pubkey_obj = Ed25519PublicKey.from_public_bytes(solana_tx_signer_pubkey)
        solana_tx_signer_pubkey_obj.verify(solana_tx_signature, solana_tx_bytes[65:])
