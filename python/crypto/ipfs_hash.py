#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# Copyright (c) 2022 Nicolas Iooss
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
"""InterPlanetary File System (IPFS) hash

IPFS (https://ipfs.tech/) uses a specific hash to compute the content ID of a
file. It is not direcly the hash of the file.

The official container for Kubo (https://github.com/ipfs/kubo), one of the main
implementations of IPFS, enables computing the Content Identifier (CID) of any
data. But it is quite verbose

    $ echo Hello > myfile
    $ podman run --rm --network=none -v "$(pwd):/dir" -it docker.io/ipfs/kubo add -n /dir/myfile
    Changing user to ipfs
    ipfs version 0.15.0
    generating ED25519 keypair...done
    peer identity: 12D3KooWHbmGWbiMZ8BejWKQbVmq1GgCfvagJKGoWrK8eGmA1zKG
    initializing IPFS node at /data/ipfs
    to get started, enter:

        ipfs cat /ipfs/QmQPeNsJPyVWPFDVHb77w8G42Fvo15z4bG2X8D2GhfbSXc/readme

    added QmY9cxiHqTFoWamkQVkpmmqzBrY3hCBEL2XNu3NtX74Fuu myfile
     6 B / 6 B [===========================================================] 100.00%

This scripts makes it easier.

Specifications:
- https://github.com/multiformats/cid/blob/5d242ef99383ca05ef2f7e24cfc84f541716232e/README.md
- https://docs.ipfs.tech/concepts/content-addressing/#cid-versions
- https://dag.ipfs.tech/ visualizes the Merkle Directed Acyclic Graph (DAG) of a file

There are some IPFS gateways which are available (https://ipfs.github.io/public-gateway-checker/):
- https://ipfs.io/ipfs/QmQPeNsJPyVWPFDVHb77w8G42Fvo15z4bG2X8D2GhfbSXc/readme
- https://cloudflare-ipfs.com/ipfs/QmQPeNsJPyVWPFDVHb77w8G42Fvo15z4bG2X8D2GhfbSXc/
- https://bafybeia6po64b6tfqq73lckadrhpihg2oubaxgqaoushquhcek46y3zumm.ipfs.cf-ipfs.com/
- https://gateway.pinata.cloud/ipfs/QmQPeNsJPyVWPFDVHb77w8G42Fvo15z4bG2X8D2GhfbSXc/readme
- https://ipfs.filebase.io/ipfs/QmQPeNsJPyVWPFDVHb77w8G42Fvo15z4bG2X8D2GhfbSXc/
"""
import argparse
import base64
import enum
import hashlib
from pathlib import Path
import re
from typing import List, Optional, Tuple, Union


@enum.unique
class MultiCodec(enum.IntEnum):
    """Multicodec table

    Specification: https://github.com/multiformats/multicodec
    """

    IDENTITY = 0x00

    CID_V1 = 0x01
    CID_V2 = 0x02
    CID_V3 = 0x03

    IP4 = 0x04
    TCP = 0x06

    SHA1 = 0x11
    SHA2_256 = 0x12
    SHA2_512 = 0x13
    SHA3_512 = 0x14
    SHA3_384 = 0x15
    SHA3_256 = 0x16
    SHA3_224 = 0x17
    SHA2_384 = 0x20
    MURMUR3_X64_64 = 0x22

    IP6 = 0x29
    PATH = 0x2F

    MULTICODEC = 0x30
    MULTIHASH = 0x31
    MULTIADDR = 0x32
    MULTIBASE = 0x33

    DNS = 0x35
    DNS4 = 0x36
    DNS6 = 0x37
    DNSADDR = 0x38

    PROTOBUF = 0x50
    CBOR = 0x51
    RAW = 0x55
    DAG_PB = 0x70  # MerkleDAG Protobuf
    DAG_CBOR = 0x71  # MerkleDAG CBOR
    LIBP2P_KEY = 0x72
    GIT_RAW = 0x78

    ETH_BLOCK = 0x90
    ETH_BLOCK_LIST = 0x91
    ETH_TX_TRIE = 0x92
    ETH_TX = 0x93
    ETH_TX_RECEIPT_TRIE = 0x94
    ETH_TX_RECEIPT = 0x95
    ETH_STATE_TRIE = 0x96
    ETH_ACCOUNT_SNAPSHOT = 0x97
    ETH_STORAGE_TRIE = 0x98
    ETH_RECEIPT_LOG_TRIE = 0x99
    ETH_RECEIPT_LOG = 0x9A

    BITCOIN_BLOCK = 0xB0
    BITCOIN_TX = 0xB1
    BITCOIN_WITNESS_COMMITMENT = 0xB2

    ZCASH_BLOCK = 0xC0
    ZCASH_TX = 0xC1

    STELLAR_BLOCK = 0xD0
    STELLAR_TX = 0xD1

    IPLD = 0xE2
    IPFS = 0xE3
    SWARM = 0xE4
    IPNS = 0xE5
    DNSLINK = 0xE8

    UDP = 0x0111

    P2P_CIRCUIT = 0x0122

    DAG_JSON = 0x0129

    UNIX = 0x0196

    P2P = 0x01A5
    HTTPS = 0x01BB
    ONION = 0x01BC
    ONION3 = 0x01BD
    TLS = 0x01C0
    NOISE = 0x01C6
    QUIC = 0x01CC
    WS = 0x01DD
    WSS = 0x01DE
    P2P_WEBSOCKET_STAR = 0x01DF
    HTTP = 0x01E0

    JSON = 0x0200

    LIBP2P_PEER_RECORD = 0x0301
    LIBP2P_RELAY_RSVP = 0x0302

    SHA2_256_TRUNC254_PADDED = 0x1012
    SHA2_224 = 0x1013
    SHA2_512_224 = 0x1014
    SHA2_512_256 = 0x1015

    BLAKE2B_256 = 0xB220

    POSEIDON_BLS12_381_AC2_FC1 = 0xB401
    POSEIDON_BLS12_381_AC2_FC1_SC = 0xB402

    FIL_COMMITMENT_UNSEALED = 0xF101
    FIL_COMMITMENT_SEALED = 0xF102

    PLAINTEXTV2 = 0x706C61


BASE36_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
assert len(BASE36_ALPHABET) == 36


def base36_encode(data: bytes) -> str:
    """Encode some data using Base36 alphabet"""
    value = int.from_bytes(data, "big")
    leading_zeros = len(data) - ((value.bit_length() + 7) // 8)
    assert leading_zeros >= 0 and data.startswith(b"\0" * leading_zeros)  # Sanity check
    result = []
    while value:
        value, number = divmod(value, 36)
        result.append(BASE36_ALPHABET[number])
    return ("0" * leading_zeros) + "".join(result[::-1])


def base36_decode(data: str, size: Optional[int] = None) -> bytes:
    """Decode some data encoded using Base36 alphabet"""
    value = 0
    leading_zeros = 0
    for char in data.upper():
        value = value * 36 + BASE36_ALPHABET.index(char)
        if value == 0:
            leading_zeros += 1
    if size is None:
        size = leading_zeros + (value.bit_length() + 7) // 8
    return value.to_bytes(size, "big")


BASE58_BITCOIN_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
assert len(BASE58_BITCOIN_ALPHABET) == 58


def base58btc_encode(data: bytes) -> str:
    """Encode some data using Base58 Bitcoin alphabet"""
    value = int.from_bytes(data, "big")
    leading_zeros = len(data) - ((value.bit_length() + 7) // 8)
    assert leading_zeros >= 0 and data.startswith(b"\0" * leading_zeros)  # Sanity check
    result = []
    while value:
        value, number = divmod(value, 58)
        result.append(BASE58_BITCOIN_ALPHABET[number])
    return (BASE58_BITCOIN_ALPHABET[:1] * leading_zeros) + "".join(result[::-1])


def base58btc_decode(data: str, size: Optional[int] = None) -> bytes:
    """Decode some data encoded using Base58 Bitcoin alphabet"""
    value = 0
    leading_zeros = 0
    for char in data:
        value = value * 58 + BASE58_BITCOIN_ALPHABET.index(char)
        if value == 0:
            leading_zeros += 1
    if size is None:
        size = leading_zeros + (value.bit_length() + 7) // 8
    return value.to_bytes(size, "big")


def multibase_decode(data_str: str) -> bytes:
    """Decode a multibase-encoded string

    Specification: https://github.com/multiformats/multibase
    """
    if data_str.startswith("0x00"):
        return data_str[4:].encode()
    if data_str.startswith("0"):  # binary
        assert (len(data_str) % 8) == 1
        return int(data_str[1:], 2).to_bytes(len(data_str) // 8, "big")
    if data_str.startswith("7"):  # octal
        bit_length = (len(data_str) - 1) * 3
        data_int = int(data_str[1:], 8) >> (bit_length % 8)
        return data_int.to_bytes(bit_length // 8, "big")
    if data_str.startswith("9"):  # decimal
        count_zero = 0
        while 1 + count_zero < len(data_str) and data_str[1 + count_zero] == "0":
            count_zero += 1
        data_int = int(data_str[1:], 10)
        return b"\0" * count_zero + data_int.to_bytes((data_int.bit_length() + 7) // 8, "big")
    if data_str.startswith("f") or data_str.startswith("F"):  # hexadecimal
        assert (len(data_str) % 2) == 1
        return bytes.fromhex(data_str[1:])
    if data_str.startswith("v"):  # base32hex lower no padding
        padding = "=" * ((9 - len(data_str)) & 7)
        return base64.b32hexdecode(data_str[1:] + padding, casefold=True)
    if data_str.startswith("V"):  # base32hex upper no padding
        padding = "=" * ((9 - len(data_str)) & 7)
        return base64.b32hexdecode(data_str[1:] + padding)
    if data_str.startswith("t"):  # base32hex lower with padding
        return base64.b32hexdecode(data_str[1:], casefold=True)
    if data_str.startswith("T"):  # base32hex upper with padding
        return base64.b32hexdecode(data_str[1:])
    if data_str.startswith("b"):  # base32 lower no padding
        padding = "=" * ((9 - len(data_str)) & 7)
        return base64.b32decode(data_str[1:] + padding, casefold=True)
    if data_str.startswith("B"):  # base32 upper no padding
        padding = "=" * ((9 - len(data_str)) & 7)
        return base64.b32decode(data_str[1:] + padding)
    if data_str.startswith("c"):  # base32 lower with padding
        return base64.b32decode(data_str[1:], casefold=True)
    if data_str.startswith("C"):  # base32 upper with padding
        return base64.b32decode(data_str[1:])
    if data_str.startswith("k"):  # base36 lower with padding
        return base36_decode(data_str[1:])
    if data_str.startswith("K"):  # base36 upper with padding
        return base36_decode(data_str[1:])
    if data_str.startswith("z"):  # base58 Bitcoin
        return base58btc_decode(data_str[1:])
    if data_str.startswith("m"):  # base64 no padding
        padding = "=" * ((5 - len(data_str)) & 3)
        return base64.b64decode(data_str[1:] + padding)
    if data_str.startswith("M"):  # base64 with padding
        return base64.b64decode(data_str[1:])
    if data_str.startswith("u"):  # base64url no padding
        return base64.urlsafe_b64decode(data_str[1:])
    if data_str.startswith("U"):  # base64url with padding
        return base64.urlsafe_b64decode(data_str[1:])
    raise NotImplementedError("Unknown multibase encoding character {!r}".format(data_str[:1]))


def decode_varint(data: bytes) -> Tuple[int, bytes]:
    """Decode an unsigned variable integer and return int and the remaining

    Specification: https://github.com/multiformats/unsigned-varint
    """
    value = 0
    offset = 0
    while offset < len(data):
        current_byte = data[offset]
        value |= (current_byte & 0x7F) << (7 * offset)
        offset += 1
        if not (current_byte & 0x80):
            return value, data[offset:]
    raise ValueError("data too short to hold a varint")


def encode_varint(value: int) -> bytes:
    current_bytes = []
    while value >= 0x80:
        current_bytes.append(0x80 | (value & 0x7F))
        value >>= 7
    current_bytes.append(value)
    return bytes(current_bytes)


class CID:
    """IPFS Content Identifier (CID)

    Specification: https://github.com/multiformats/cid
    """

    def __init__(
        self,
        version: int,
        encoding: str,
        multicodec: Union[int, MultiCodec],
        multihash_code: Union[int, MultiCodec],
        multihash_out: bytes,
    ) -> None:
        self.version = version
        self.encoding = encoding
        if isinstance(multicodec, MultiCodec):
            self.multicodec = multicodec
        else:
            self.multicodec = MultiCodec(multicodec)
        if isinstance(multihash_code, MultiCodec):
            self.multihash_code = multihash_code
        else:
            self.multihash_code = MultiCodec(multihash_code)
        self.multihash_out = multihash_out

    def __repr__(self) -> str:
        return "CID({}, {!r}, {}, {}, {!r})".format(
            self.version, self.encoding, self.multicodec.name, self.multihash_code.name, self.multihash_out.hex()
        )

    @classmethod
    def decode(cls, cid: str) -> "CID":
        """Decode a given CID"""
        # Support URLs
        matches = re.match(r"^https://ipfs.io/ipfs/([0-9A-Za-z]+)", cid)
        if matches:
            cid = matches.group(1)
        if len(cid) == 46 and cid.startswith("Qm"):  # CIDv0
            raw_cid = base58btc_decode(cid)
            assert raw_cid.startswith(b"\x12\x20")  # SHA256, 32 bytes
            assert len(raw_cid) == 0x22
            return cls(0, "", MultiCodec.DAG_PB, MultiCodec.SHA2_256, raw_cid[2:])
        else:
            raw_cid = multibase_decode(cid)
            cid_version, raw_cid = decode_varint(raw_cid)
            if cid_version != 1:
                raise NotImplementedError(
                    "CIDv{} {}: unknown version with hex {}".format(cid_version, cid, raw_cid.hex())
                )

            multicodec, multihash = decode_varint(raw_cid)
            multihash_code, multihash = decode_varint(multihash)
            multihash_size, multihash_out = decode_varint(multihash)
            if multihash_size != len(multihash_out):
                raise ValueError("Unexpected hash size {} != {}", multihash_size, len(multihash_out))
            encoding = "0x00" if cid.startswith("0x00") else cid[:1]
            return cls(cid_version, encoding, multicodec, multihash_code, multihash_out)

    def encode(self, version: Optional[int] = None, encoding: Optional[str] = None) -> str:
        if version is None:
            version = self.version
        if encoding is None:
            encoding = self.encoding
            if version == 1 and not encoding:
                encoding = "b"

        if version == 0:
            if self.multicodec != MultiCodec.DAG_PB:
                raise ValueError("Unable to encode a CIDv0 with multicodec {}".format(self.multicodec.name))
            return base58btc_encode(
                encode_varint(self.multihash_code) + encode_varint(len(self.multihash_out)) + self.multihash_out
            )

        if version == 1:
            raw_cid = (
                encode_varint(version)
                + encode_varint(self.multicodec)
                + encode_varint(self.multihash_code)
                + encode_varint(len(self.multihash_out))
                + self.multihash_out
            )
            if encoding == "b":
                return "b" + base64.b32encode(raw_cid).decode("ascii").rstrip("=").lower()
            if encoding == "B":
                return "B" + base64.b32encode(raw_cid).decode("ascii").rstrip("=")
            if encoding == "k":
                return "k" + base36_encode(raw_cid).lower()
            if encoding == "K":
                return "K" + base36_encode(raw_cid)
            raise NotImplementedError("Unsupported CIDv1 multibase encoding to {!r}".format(encoding))

        raise NotImplementedError("Unsupported CIDv{} encoding".format(version))

    def gateway_urls(self, version: Optional[int] = None, encoding: Optional[str] = None) -> List[str]:
        """Get URL to IPFS gateways related to this object

        Documentation of IPFS gateways: https://docs.ipfs.tech/concepts/ipfs-gateway/
        """
        if version is None and self.multicodec == MultiCodec.DAG_PB:
            # CIDv0 is available
            return [
                "https://ipfs.io/ipfs/{}".format(self.encode(version=0)),
                "https://ipfs.io/ipfs/{}".format(self.encode(version=1, encoding=encoding)),
                "https://cloudflare-ipfs.com/ipfs/{}".format(self.encode(version=0)),
                "https://cloudflare-ipfs.com/ipfs/{}".format(self.encode(version=1, encoding=encoding)),
                "https://{}.ipfs.cf-ipfs.com/".format(self.encode(version=1, encoding=encoding)),
                "https://gateway.pinata.cloud/ipfs/{}".format(self.encode(version=0)),
                "https://gateway.pinata.cloud/ipfs/{}".format(self.encode(version=1, encoding=encoding)),
                "https://ipfs.filebase.io/ipfs/{}".format(self.encode(version=0)),
                "https://ipfs.filebase.io/ipfs/{}".format(self.encode(version=1, encoding=encoding)),
            ]
        elif version == 0:
            return [
                "https://ipfs.io/ipfs/{}".format(self.encode(version=0)),
                "https://cloudflare-ipfs.com/ipfs/{}".format(self.encode(version=0)),
                "https://gateway.pinata.cloud/ipfs/{}".format(self.encode(version=0)),
                "https://ipfs.filebase.io/ipfs/{}".format(self.encode(version=0)),
            ]
        else:
            return [
                "https://ipfs.io/ipfs/{}".format(self.encode(version=version, encoding=encoding)),
                "https://cloudflare-ipfs.com/ipfs/{}".format(self.encode(version=version, encoding=encoding)),
                "https://{}.ipfs.cf-ipfs.com/".format(self.encode(version=version, encoding=encoding)),
                "https://gateway.pinata.cloud/ipfs/{}".format(self.encode(version=version, encoding=encoding)),
                "https://ipfs.filebase.io/ipfs/{}".format(self.encode(version=version, encoding=encoding)),
            ]


def cid_dagpb_from_raw_file_sha256(file_content: bytes) -> Tuple[bytes, int]:
    """Compute the DAG-PB Content ID of a raw file, without chunking

    It crafts Protobuf messages defined in two files:

    https://github.com/ipfs/go-merkledag/blob/v0.8.0/pb/merkledag.proto

        // An IPFS MerkleDAG Link
        message PBLink {

          // multihash of the target object
          optional bytes Hash = 1;

          // utf string name. should be unique per object
          optional string Name = 2;

          // cumulative size of target object
          optional uint64 Tsize = 3;
        }

        // An IPFS MerkleDAG Node
        message PBNode {

          // refs to other objects
          repeated PBLink Links = 2;

          // opaque user data
          optional bytes Data = 1;
        }

    https://github.com/ipfs/go-unixfs/blob/v0.4.1/pb/unixfs.proto

        message Data {
            enum DataType {
                Raw = 0;
                Directory = 1;
                File = 2;
                Metadata = 3;
                Symlink = 4;
                HAMTShard = 5;
            }

            required DataType Type = 1;
            optional bytes Data = 2;
            optional uint64 filesize = 3;
            repeated uint64 blocksizes = 4;

            optional uint64 hashType = 5;
            optional uint64 fanout = 6;
        }

        message Metadata {
            optional string MimeType = 1;
        }
    """
    # Build the protobuf
    encoded_size = encode_varint(len(file_content))
    unixfs_data = b"\x08\x02"  # "Type: File"
    if file_content:
        unixfs_data += b"\x12" + encoded_size + file_content  # Data
    unixfs_data += b"\x18" + encoded_size  # filesize

    # Craft a "Data: unixfs_data" protobuf message
    pb_dag = b"\x0a" + encode_varint(len(unixfs_data)) + unixfs_data
    return hashlib.sha256(pb_dag).digest(), len(pb_dag)


def cid_dagpb_from_raw_file(file_content: bytes) -> CID:
    """Compute the DAG-PB Content ID of a raw file, without chunking"""
    pb_dag_hash, _ = cid_dagpb_from_raw_file_sha256(file_content)
    return CID(0, "", MultiCodec.DAG_PB, MultiCodec.SHA2_256, pb_dag_hash)


def cid_dagpb_from_file(file_content: bytes, block_size: int = 262144, links_per_block: int = 174) -> CID:
    """Compute the DAG-PB Content ID of a file like 'ipfs add' (with kubo)

    By default, 'ipfs add' splits the file in chunks of 256 KB = 262144 bytes:
    https://github.com/ipfs/kubo/blob/v0.16.0/core/commands/add.go#L99-L106

    The algorithm which is used to create links by default is "balanced":
    https://github.com/ipfs/go-unixfs/blob/v0.4.1/importer/balanced/builder.go

    The maximal number of links per blocks is hard-coded in
    https://github.com/ipfs/go-unixfs/blob/v0.4.1/importer/helpers/helpers.go#L28

        DefaultLinksPerBlock = roughLinkBlockSize / roughLinkSize
            = (8 * 1024) / (34 + 8 + 5)
            = 174.29787234042553 rounded to 174
    """
    if len(file_content) == 0:  # or "< block_size"
        return cid_dagpb_from_raw_file(file_content)

    # Split into chunks
    pb_dag_hashes: List[Tuple[bytes, int, int]] = []
    for offset in range(0, len(file_content), block_size):
        off_end = min(offset + block_size, len(file_content))
        block = file_content[offset:off_end]
        # Craft a PBLink message with a SHA256 hash
        pb_dag_hash, pb_dag_len = cid_dagpb_from_raw_file_sha256(block)
        pb_dag_hashes.append((pb_dag_hash, len(block), pb_dag_len))

    # Group the chunks according to links_per_block
    while len(pb_dag_hashes) > 1:
        new_pb_dag_hashes: List[Tuple[bytes, int, int]] = []
        for part_index in range(0, len(pb_dag_hashes), links_per_block):
            part_index_end = min(part_index + links_per_block, len(pb_dag_hashes))
            pb_dag_hash_ctx = hashlib.sha256()
            sum_total_size = 0
            sum_block_sizes = 0
            encoded_block_sizes: List[bytes] = []

            for pb_dag_hash, block_size, total_size in pb_dag_hashes[part_index:part_index_end]:
                # Craft a "Data: unixfs_data" protobuf message
                # {Hash=1: {SHA256=2: {hash}}, name=2: "", Tsize=3: total_size}
                pblink = b"\x0a\x22\x12\x20" + pb_dag_hash + b"\x12\x00\x18" + encode_varint(total_size)
                pbnode_link = b"\x12" + encode_varint(len(pblink)) + pblink
                pb_dag_hash_ctx.update(pbnode_link)
                sum_total_size += total_size + len(pbnode_link)
                sum_block_sizes += block_size
                encoded_block_sizes.append(b"\x20" + encode_varint(block_size))

            # Add the Data part with {Type=1: 2=File, filesize=3: len(file), blocksizes=4: [block_size...]}
            unixfs_data = b"\x08\x02\x18" + encode_varint(sum_block_sizes) + b"".join(encoded_block_sizes)
            pbnode_data = b"\x0a" + encode_varint(len(unixfs_data)) + unixfs_data
            pb_dag_hash_ctx.update(pbnode_data)
            sum_total_size += len(pbnode_data)
            pb_dag_hash = pb_dag_hash_ctx.digest()
            new_pb_dag_hashes.append((pb_dag_hash, sum_block_sizes, sum_total_size))

        pb_dag_hashes = new_pb_dag_hashes

    return CID(0, "", MultiCodec.DAG_PB, MultiCodec.SHA2_256, pb_dag_hashes[0][0])


def run_self_tests() -> None:
    """Check that the implementations are correct"""
    # https://github.com/keis/base58/blob/v2.1.1/test_base58.py
    assert base58btc_encode(b"") == ""
    assert base58btc_encode(b"hello world") == "StV1DL6CwTryKyV"
    assert base58btc_encode(b"\0\0hello world") == "11StV1DL6CwTryKyV"

    assert base58btc_decode("") == b""
    assert base58btc_decode("StV1DL6CwTryKyV") == b"hello world"
    assert base58btc_decode("11StV1DL6CwTryKyV") == b"\0\0hello world"

    # https://github.com/multiformats/multibase/blob/5296976a6b8d17015b636421b7f9d82a0206dd05/rfcs/Base36.md
    assert base36_encode(b"") == ""
    assert base36_encode(b"\x00\x01") == "01"
    assert base36_encode(b"\x00\x00\xff") == "0073"
    assert base36_encode(b"\x01\x00") == "74"
    assert base36_encode(b"\x00\x01\x00") == "074"

    assert base36_decode("") == b""
    assert base36_decode("01") == b"\x00\x01"
    assert base36_decode("0073") == b"\x00\x00\xff"
    assert base36_decode("74") == b"\x01\x00"
    assert base36_decode("074") == b"\x00\x01\x00"

    # https://github.com/tonyseek/python-base36/blob/v0.1.1/README.rst
    assert base36_encode(int.to_bytes(19930503, 4, "big")) == "BV6H3"
    assert int.from_bytes(base36_decode("BV6H3"), "big") == 19930503

    # https://stackoverflow.com/questions/1181919/python-base-36-encoding
    assert base36_encode(int.to_bytes(1412823931503067241, 8, "big")) == "AQF8AA0006EH"
    assert int.from_bytes(base36_decode("AQF8AA0006EH"), "big") == 1412823931503067241

    # https://ipld.io/specs/codecs/dag-pb/spec/#zero-length-blocks
    cidv0 = "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n"
    cidv1b = "bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
    assert hashlib.sha256(b"").digest() == bytes.fromhex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert base58btc_decode(cidv0) == bytes.fromhex(
        "1220e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    cidv0_obj = CID.decode(cidv0)
    assert cidv0_obj.version == 0
    assert cidv0_obj.multicodec == MultiCodec.DAG_PB
    assert cidv0_obj.multihash_code == MultiCodec.SHA2_256
    assert cidv0_obj.multihash_out == bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert cidv0_obj.encode() == cidv0
    assert cidv0_obj.encode(version=1, encoding="b") == cidv1b

    assert multibase_decode(cidv1b) == bytes.fromhex(
        "01701220e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    cidv1_obj = CID.decode(cidv1b)
    assert cidv1_obj.version == 1
    assert cidv1_obj.multicodec == MultiCodec.DAG_PB
    assert cidv1_obj.multihash_code == MultiCodec.SHA2_256
    assert cidv1_obj.multihash_out == bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert cidv1_obj.encode() == cidv1b
    assert cidv1_obj.encode(version=0) == cidv0

    # https://docs.ipfs.tech/concepts/ipns/#how-ipns-works
    # https://cid.ipfs.tech/#k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8
    ipns_key = CID.decode("k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8")
    assert ipns_key.version == 1
    assert ipns_key.multicodec == MultiCodec.LIBP2P_KEY
    assert ipns_key.multihash_code == MultiCodec.IDENTITY
    assert ipns_key.multihash_out == bytes.fromhex(
        "08011220e4680b2f8c8d21090e6aa327f1bb342ab8e7d9238f1e35831a54d6a8f5c91124"
    )
    assert ipns_key.encode() == "k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8"
    assert ipns_key.encode(encoding="b") == "bafzaajaiaejcbzdibmxyzdjbbehgvizh6g5tikvy47mshdy6gwbruvgwvd24seje"

    # https://ipfs.github.io/public-gateway-checker/
    cidv0 = "Qmaisz6NMhDB51cCvNWa1GMS7LU1pAxdF4Ld6Ft9kZEP2a"
    cidv1b = "bafybeifx7yeb55armcsxwwitkymga5xf53dxiarykms3ygqic223w5sk3m"
    assert base58btc_decode(cidv0) == bytes.fromhex(
        "1220b7fe081ef41160a57b591356186076e5eec77402385325bc1a0816b5bb764adb"
    )
    cidv0_obj = CID.decode(cidv0)
    assert cidv0_obj.version == 0
    assert cidv0_obj.multicodec == MultiCodec.DAG_PB
    assert cidv0_obj.multihash_code == MultiCodec.SHA2_256
    assert cidv0_obj.multihash_out == bytes.fromhex("b7fe081ef41160a57b591356186076e5eec77402385325bc1a0816b5bb764adb")
    assert cidv0_obj.encode() == cidv0
    assert cidv0_obj.encode(version=1, encoding="b") == cidv1b

    assert multibase_decode(cidv1b) == bytes.fromhex(
        "01701220b7fe081ef41160a57b591356186076e5eec77402385325bc1a0816b5bb764adb"
    )
    cidv1_obj = CID.decode(cidv1b)
    assert cidv1_obj.version == 1
    assert cidv1_obj.multicodec == MultiCodec.DAG_PB
    assert cidv1_obj.multihash_code == MultiCodec.SHA2_256
    assert cidv1_obj.multihash_out == bytes.fromhex("b7fe081ef41160a57b591356186076e5eec77402385325bc1a0816b5bb764adb")
    assert cidv1_obj.encode() == cidv1b
    assert cidv1_obj.encode(version=0) == cidv0

    # Test to host anything, on https://bafkqadcimvwgy3zmebevarstee.ipfs.cf-ipfs.com/
    hello_cid_obj = CID(1, "b", MultiCodec.RAW, MultiCodec.IDENTITY, b"Hello, IPFS!")
    assert hello_cid_obj.encode() == "bafkqadcimvwgy3zmebevarstee"
    assert CID.decode("bafkqadcimvwgy3zmebevarstee").multihash_out == b"Hello, IPFS!"

    # "ipfs add hello.txt" with "Hello\n"
    cidv0_obj = CID.decode("QmY9cxiHqTFoWamkQVkpmmqzBrY3hCBEL2XNu3NtX74Fuu")
    assert cidv0_obj.multihash_out == bytes.fromhex("91c180f281a2861f291d3a49f8e24a02ce7fd8fd8f5c71b9d6d41166455a02cc")
    # This is Protobuf: 1 {1: 2, 2: "Hello\n", 3: 6} (in /data/ipfs/...)
    # Which is PBNode {Data: {Type: File, Data: "Hello\n", filesize: 6}}
    assert hashlib.sha256(b"\x0a\x0c\x08\x02\x12\x06Hello\n\x18\x06").digest() == bytes.fromhex(
        "91c180f281a2861f291d3a49f8e24a02ce7fd8fd8f5c71b9d6d41166455a02cc"
    )
    assert cid_dagpb_from_file(b"Hello\n").encode() == "QmY9cxiHqTFoWamkQVkpmmqzBrY3hCBEL2XNu3NtX74Fuu"

    # "ipfs add empty" with an empty file
    cidv0_obj = CID.decode("QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH")
    assert cidv0_obj.multihash_out == bytes.fromhex("bfccda787baba32b59c78450ac3d20b633360b43992c77289f9ed46d843561e6")
    # This is Protobuf: 1 {1: 2, 3: 0}
    # Which is PBNode {Data: {Type: File, filesize: 0}}
    assert hashlib.sha256(b"\x0a\x04\x08\x02\x18\x00").digest() == bytes.fromhex(
        "bfccda787baba32b59c78450ac3d20b633360b43992c77289f9ed46d843561e6"
    )
    assert cid_dagpb_from_file(b"").encode() == "QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH"

    # Try chunking with block size: printf ab > ab && ipfs add --chunker size-1 ab
    cidv0_obj = CID.decode("QmPbeHNLMBbUfMbCkixtSKaXvh1sipPaw7FDRo6hjuPeeb")
    assert cidv0_obj.multihash_out == bytes.fromhex("12b2eab343316f64e75834916589952022248ec43e69efe565790e6cbbcf4e28")
    # $ ipfs ls --headers QmPbeHNLMBbUfMbCkixtSKaXvh1sipPaw7FDRo6hjuPeeb
    # Hash                                           Size Name
    # QmfDmsHTywy6L9Ne5RXsj5YumDedfBLMvCvmaxjBoe6w4d 1
    # QmQLd9KEkw5eLKfr9VwfthiWbuqa9LXhRchWqD4kRPPWEf 1
    assert cid_dagpb_from_file(b"a").encode() == "QmfDmsHTywy6L9Ne5RXsj5YumDedfBLMvCvmaxjBoe6w4d"
    assert cid_dagpb_from_file(b"b").encode() == "QmQLd9KEkw5eLKfr9VwfthiWbuqa9LXhRchWqD4kRPPWEf"
    expected_pb = bytes.fromhex(
        "12 28"  # PBNode: repeated PBLink Links = 2 {
        + "0a 22 12 20 fad3b4b8270ea30f09c1364b990db3351b2f720115b774071f4cc4e2ba25dfc2"  # bytes Hash = 1
        + "12 00 18 09"  # string Name = 2 : 0 ; uint64 Tsize = 3 : 9 }
        + "12 28"  # PBNode: repeated PBLink Links = 2 {
        + "0a 22 12 20 1db59a982e018221f8f97b9044f13d58b8ed5c4b7943fe48cad9ca8f68f9c23c"  # bytes Hash = 1
        + "12 00 18 09"  # string Name = 2 : 0 ; uint64 Tsize = 3 : 9 }
        + "0a 08"  # PBNode: bytes Data = 1 { (which is unixfs.Data)
        + "08 02 18 02 20 01 20 01"  # Type=1 : 2=File ; filesize=3 : 2 ; blocksizes=4 : [1, 1] }
    )
    assert hashlib.sha256(expected_pb).digest() == bytes.fromhex(
        "12b2eab343316f64e75834916589952022248ec43e69efe565790e6cbbcf4e28"
    )
    assert cid_dagpb_from_file(b"ab", block_size=1).encode() == "QmPbeHNLMBbUfMbCkixtSKaXvh1sipPaw7FDRo6hjuPeeb"

    # Try chunking with block size and one level of hierarchy:
    # python -c 'import sys;sys.stdout.write("ab" * 174)' > ab-174 && ipfs add --chunker size-2 ab-174
    cidv0_obj = CID.decode("QmQ7bXhmbRw1uU2hGP1mEfdcAjb8dbRUVhXU7MHgzDiBNp")
    assert cidv0_obj.multihash_out == bytes.fromhex("1a5f3a79c0642176f19a3fa5a60936c5919a9f31658ad3db8811e09bf47f4de1")
    # $ ipfs ls --headers QmQ7bXhmbRw1uU2hGP1mEfdcAjb8dbRUVhXU7MHgzDiBNp
    # Hash                                           Size Name
    # QmYfhYCLvZCNdb6SQiuPmL6qFTLtW4AtT88PP9FmhN8SiR 2
    # QmYfhYCLvZCNdb6SQiuPmL6qFTLtW4AtT88PP9FmhN8SiR 2
    # QmYfhYCLvZCNdb6SQiuPmL6qFTLtW4AtT88PP9FmhN8SiR 2
    # ...
    assert cid_dagpb_from_file(b"ab").encode() == "QmYfhYCLvZCNdb6SQiuPmL6qFTLtW4AtT88PP9FmhN8SiR"
    expected_pb = bytes.fromhex(
        "12 28"  # PBNode: repeated PBLink Links = 2 {
        + "0a 22 12 20 99761a8218902ec1f4e294c93bc835852073d5638f7c692d5c9a68354b40464e"  # bytes Hash = 1
        + "12 00 18 0a"  # string Name = 2 : 0 ; uint64 Tsize = 3 : 10 }
    ) * 174 + bytes.fromhex(
        "0a e102"  # PBNode: bytes Data = 1 { (which is unixfs.Data)
        + "08 02 18 dc02"  # Type=1 : 2=File ; filesize=0x15c=348 : 2
        + ("20 02") * 174  # blocksizes=4 : [2, 2, ...] }
    )
    assert hashlib.sha256(expected_pb).digest() == bytes.fromhex(
        "1a5f3a79c0642176f19a3fa5a60936c5919a9f31658ad3db8811e09bf47f4de1"
    )
    assert cid_dagpb_from_file(b"ab" * 174, block_size=2).encode() == "QmQ7bXhmbRw1uU2hGP1mEfdcAjb8dbRUVhXU7MHgzDiBNp"

    # Try chunking with block size and two levels of hierarchy:
    # python -c 'import sys;sys.stdout.write("ab" * 175)' > ab-175 && ipfs add --chunker size-2 ab-175
    cidv0_obj = CID.decode("QmZs63KnTCwvU8H3mT5uUbTyah9BqwKv1EedpVFJFBXRd3")
    assert cidv0_obj.multihash_out == bytes.fromhex("ab3c9f69a36dfc6ca49af664beb2e7fec07e2f7dec0f5f9972456d5b15e60cda")
    # $ ipfs ls --headers QmZs63KnTCwvU8H3mT5uUbTyah9BqwKv1EedpVFJFBXRd3
    # Hash                                           Size Name
    # QmQ7bXhmbRw1uU2hGP1mEfdcAjb8dbRUVhXU7MHgzDiBNp 348
    # QmWNXagM3Y9fYhVoDayersCxJ5FLbHKkZ3nAWjqi8aR8VL 2
    # $ ipfs ls --headers QmWNXagM3Y9fYhVoDayersCxJ5FLbHKkZ3nAWjqi8aR8VL
    # Hash                                           Size Name
    # QmYfhYCLvZCNdb6SQiuPmL6qFTLtW4AtT88PP9FmhN8SiR 2
    expected_pb = bytes.fromhex(
        "12 29"  # PBNode: repeated PBLink Links = 2 {
        + "0a 22 12 20 1a5f3a79c0642176f19a3fa5a60936c5919a9f31658ad3db8811e09bf47f4de1"  # bytes Hash = 1
        + "12 00 18 bc49"  # string Name = 2 : 0 ; uint64 Tsize = 3 : 0x24bc=9404 }
        + "12 28"  # PBNode: repeated PBLink Links = 2 {
        + "0a 22 12 20 775898e9123031855088956245a47d5da11c905478c8da313302f860083b9cd7"  # bytes Hash = 1
        + "12 00 18 3c"  # string Name = 2 : 0 ; uint64 Tsize = 3 : 0x3c }
        + "0a 0a"  # PBNode: bytes Data = 1 { (which is unixfs.Data)
        + "08 02 18 de02 20 dc02 20 02"  # Type=1 : 2=File ; filesize=0x15e=350 : 2 ; blocksizes=4 : [0x15c, 2] }
    )
    assert hashlib.sha256(expected_pb).digest() == bytes.fromhex(
        "ab3c9f69a36dfc6ca49af664beb2e7fec07e2f7dec0f5f9972456d5b15e60cda"
    )
    assert cid_dagpb_from_file(b"ab" * 175, block_size=2).encode() == "QmZs63KnTCwvU8H3mT5uUbTyah9BqwKv1EedpVFJFBXRd3"

    # Try chunking with 3 levels of hierarchy: 174*174 = 30276
    # head -c 32768 /dev/zero > zero-32K && ipfs add --chunker size-1 zero-32K
    assert cid_dagpb_from_file(b"\0" * 32768, block_size=1).encode() == "QmSwvSMPrj5frve2PBMejVNgnac37EnqzYZULJQMnw3dxb"

    print("IPFS Hash Self tests OK")


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="IPFS Hash tool")
    parser.add_argument("path", type=Path, nargs="*", help="path to files to hash")
    parser.add_argument("-d", "--decode", type=str, nargs="+", help="decode an IPFS CID")
    parser.add_argument("-r", "--reencode", action="store_true", help="reencode the given IPFS CID")
    parser.add_argument("-u", "--url", action="store_true", help="reencode the given IPFS CID to URL")
    parser.add_argument("-s", "--block-size", type=int, default=262144, help="block size of data (default: 256 KB)")
    args = parser.parse_args(argv)

    if not args.path and not args.decode:
        run_self_tests()
        return

    if args.path:
        for file_path in args.path:
            with file_path.open("rb") as fd:
                file_content = fd.read()
            if args.block_size <= 0:
                # Do not chunk the file into blocks
                cid_obj = cid_dagpb_from_raw_file(file_content)
            else:
                cid_obj = cid_dagpb_from_file(file_content, args.block_size)
            print("{}: {}".format(file_path, cid_obj.encode()))
            if args.reencode:
                print("  CIDv1: {}".format(cid_obj.encode(version=1, encoding="b")))
            if args.url:
                for url in cid_obj.gateway_urls(encoding="b"):
                    print("  {}".format(url))

    if args.decode:
        for cid in args.decode:
            cid_obj = CID.decode(cid)
            print("CIDv{} {}".format(cid_obj.version, cid))
            print("  multicodec: {:#x} ({})".format(cid_obj.multicodec, cid_obj.multicodec.name))
            print("  multihash code: {:#x} ({})".format(cid_obj.multihash_code, cid_obj.multihash_code.name))
            print("  multihash: {}".format(cid_obj.multihash_out.hex()))
            if args.reencode:
                if cid_obj.multicodec == MultiCodec.DAG_PB:
                    print("  re-encoded CIDv0: {}".format(cid_obj.encode(version=0)))
                print("  re-encoded CIDv1 base32: {}".format(cid_obj.encode(version=1, encoding="b")))
                print("  re-encoded CIDv1 base36: {}".format(cid_obj.encode(version=1, encoding="k")))
            if args.url:
                for url in cid_obj.gateway_urls(encoding="b"):
                    print("  {}".format(url))


if __name__ == "__main__":
    main()
