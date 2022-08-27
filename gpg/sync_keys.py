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
"""Sync some PGP keys used in widely-used projects

This uses Web Key Directory (WKD) described on:
- https://wiki.gnupg.org/WKD
- https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/

For information, to use WKD in the command-line:

    gpg --auto-key-locate nodefault,wkd --locate-keys user@example.org
"""
import base64
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Union
import urllib.error
import urllib.parse
import urllib.request


KEYS_PATH = Path(__file__).parent / "keys.txt"
ALL_KEYS_PATH = Path(__file__).parent / "all_keys"

ZBASE32_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"
ZBASE32_ALPHABET_REV = {c: i for i, c in enumerate(ZBASE32_ALPHABET)}


def opgp_crc24(data: bytes) -> int:
    """Computes the CRC24 used by OpenPGP Message Format

    Specification: https://www.rfc-editor.org/rfc/rfc4880#section-6
        #define CRC24_INIT 0xB704CE
        #define CRC24_POLY 0x1864CFB
    """
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if (crc & 0x1000000) != 0:
                crc ^= 0x1864CFB
    assert 0 <= crc <= 0xFFFFFF
    return crc


def opgp_crc24_b64(data: bytes) -> str:
    """Computes the CRC24 used by OpenPGP Message Format, encoded in base64"""
    crc = opgp_crc24(data)
    return "=" + base64.b64encode(crc.to_bytes(3, "big")).decode("ascii")


def unarmor_gpg(armored: Union[bytes, str]) -> bytes:
    if isinstance(armored, str):
        lines = armored.splitlines()
    else:
        lines = armored.decode("ascii").splitlines()
    if lines[0] != "-----BEGIN PGP PUBLIC KEY BLOCK-----":
        raise ValueError(f"unexpected first line {lines[0]!r}")
    if lines[-1] != "-----END PGP PUBLIC KEY BLOCK-----":
        raise ValueError(f"unexpected last line {lines[0]!r}")
    first_empty_line = lines.index("")
    data = base64.b64decode("".join(lines[first_empty_line + 1:-2]))
    computed_checksum = opgp_crc24_b64(data)
    if lines[-2] != computed_checksum:
        raise ValueError(f"unexpected checksum {lines[-2]!r}, expected {computed_checksum}")
    return data


def zbase32_encode(data: bytes) -> str:
    """Encode some data using the z-base-32 encoding

    This encoding is specified for ZRTP protocol in
    https://www.rfc-editor.org/rfc/rfc6189.html#section-5.1.6
    and used an alphabet described as:

        This base32 encoding scheme differs from RFC 4648, and was designed
        (by Bryce Wilcox-O'Hearn) to represent bit sequences in a form that
        is convenient for human users to manipulate with minimal ambiguity.
        The unusually permuted character ordering was designed for other
        applications that use bit sequences that do not end on quintet
        boundaries.

    This hash is used by WKD and can be computed by GnuPG:

        gpg --with-wkd-hash -k yourmail@example.org
    """
    result = ""
    for idx in range(0, len(data), 5):
        result += ZBASE32_ALPHABET[(data[idx] & 0xF8) >> 3]
        if idx + 1 == len(data):
            result += ZBASE32_ALPHABET[(data[idx] & 0x07) << 2]
            break
        result += ZBASE32_ALPHABET[((data[idx] & 0x07) << 2) | ((data[idx + 1] & 0xC0) >> 6)]
        result += ZBASE32_ALPHABET[(data[idx + 1] & 0x3E) >> 1]
        if idx + 2 == len(data):
            result += ZBASE32_ALPHABET[(data[idx + 1] & 0x01) << 4]
            break
        result += ZBASE32_ALPHABET[((data[idx + 1] & 0x01) << 4) | ((data[idx + 2] & 0xF0) >> 4)]
        if idx + 3 == len(data):
            result += ZBASE32_ALPHABET[(data[idx + 2] & 0x0F) << 1]
            break
        result += ZBASE32_ALPHABET[((data[idx + 2] & 0x0F) << 1) | ((data[idx + 3] & 0x80) >> 7)]
        result += ZBASE32_ALPHABET[(data[idx + 3] & 0x7C) >> 2]
        if idx + 4 == len(data):
            result += ZBASE32_ALPHABET[(data[idx + 3] & 0x03) << 3]
            break
        result += ZBASE32_ALPHABET[((data[idx + 3] & 0x03) << 3) | ((data[idx + 4] & 0xE0) >> 5)]
        result += ZBASE32_ALPHABET[data[idx + 4] & 0x1F]
    assert len(result) == (len(data) * 8 + 4) // 5
    return result


def zbase32_decode(text: str) -> bytes:
    """Decode some data using the z-base-32 encoding"""
    result = bytearray(len(text) * 5 // 8)
    cur_byte = 0
    cur_numbits = 0
    idx = 0
    for character in text:
        value = ZBASE32_ALPHABET_REV[character]
        cur_byte = (cur_byte << 5) | value
        cur_numbits += 5
        if cur_numbits >= 8:
            cur_numbits -= 8
            result[idx] = cur_byte >> cur_numbits
            idx += 1
            cur_byte &= (1 << cur_numbits) - 1
    return bytes(result)


def get_wkd_advanced_url(email: str) -> str:
    """Craft an URL for WKD advanced method"""
    local, domain = email.split("@", 1)
    domain = domain.lower()
    local_sha1 = hashlib.sha1(local.lower().encode("ascii")).digest()
    local_b32 = zbase32_encode(local_sha1)
    params = urllib.parse.urlencode({"l": local})
    return f"https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{local_b32}?{params}"


def get_wkd_direct_url(email: str) -> str:
    """Craft an URL for WKD direct method"""
    local, domain = email.split("@", 1)
    domain = domain.lower()
    local_sha1 = hashlib.sha1(local.lower().encode("ascii")).digest()
    local_b32 = zbase32_encode(local_sha1)
    params = urllib.parse.urlencode({"l": local})
    return f"https://{domain}/.well-known/openpgpkey/hu/{local_b32}?{params}"


def self_check() -> None:
    """Verify that the algorithm computing WKD URLs work"""
    assert len(ZBASE32_ALPHABET) == 32

    # Test vector from https://github.com/matusf/z-base-32/blob/0.1.2/src/lib.rs
    assert zbase32_encode(b"asdasd") == "cf3seamuco"
    assert zbase32_decode("cf3seamuco") == b"asdasd"

    # Test vector from https://www.uriports.com/blog/setting-up-openpgp-web-key-directory/
    # assert zbase32_encode(hashlib.sha1(b"yourmail").digest()) == "hacabazoakmnagxwmkjerb9yehuwehbm"
    # -> this hash is wrong, and I don't know what username gives the SHA1
    # e61980e2f0c2962c19f45a928207e0472744702b

    # Test vector from https://metacode.biz/openpgp/web-key-directory
    assert zbase32_encode(hashlib.sha1(b"test-wkd").digest()) == "4hg7tescnttreaouu4z1izeuuyibwww1"

    # Test vector from https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/
    assert (
        get_wkd_advanced_url("Joe.Doe@Example.ORG")
        == "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe"  # noqa
    )
    assert (
        get_wkd_direct_url("Joe.Doe@Example.ORG")
        == "https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe"
    )

    # Test vector from https://wiki.gnupg.org/WKD
    assert (
        get_wkd_direct_url("bernhard.reiter@intevation.de")
        == "https://intevation.de/.well-known/openpgpkey/hu/it5sewh54rxz33fwmr8u6dy4bbz8itz4?l=bernhard.reiter"
    )


def get_pgp_key_id(raw_key: bytes) -> str:
    """Get the identifier of a key, using GnuPG"""
    # Flush stdout and stderr to prevent interleaving messages from a subprocess
    sys.stdout.flush()
    sys.stderr.flush()
    with tempfile.TemporaryDirectory(prefix="gnupghome") as tmpdir:
        # Create an empty public keyring to avoid a GnuPG message
        with (Path(tmpdir) / "pubring.kbx").open("wb"):
            pass
        output = subprocess.check_output(
            ("gpg", "--list-packets"),
            input=raw_key,
            env={
                "GNUPGHOME": tmpdir,
                "HOME": tmpdir,
            },
        )
    keyid_index = output.index(b"keyid: ") + 7
    keyid_end_index = output.index(b"\n", keyid_index)
    key_id = output[keyid_index:keyid_end_index].decode("ascii")
    assert len(key_id) == 16
    assert all(c in "0123456789ABCDEF" for c in key_id)
    return key_id


def gpg_recv_key(key_id: str) -> bytes:
    """Receive a key using GnuPG using Ubuntu keyserver https://keyserver.ubuntu.com/"""
    # Flush stdout and stderr to prevent interleaving messages from a subprocess
    sys.stdout.flush()
    sys.stderr.flush()
    with tempfile.TemporaryDirectory(prefix="gnupghome") as tmpdir:
        # Create an empty public keyring to avoid a GnuPG message
        with (Path(tmpdir) / "pubring.kbx").open("wb"):
            pass
        with (Path(tmpdir) / "trustdb.gpg").open("wb"):
            pass
        subprocess.check_output(
            ("gpg", "--keyserver", "hkps://keyserver.ubuntu.com", "--recv-keys", key_id),
            input=b"",
            env={
                "GNUPGHOME": tmpdir,
                "HOME": tmpdir,
            },
        )
        raw_key = subprocess.check_output(
            ("gpg", "--export", key_id),
            env={
                "GNUPGHOME": tmpdir,
                "HOME": tmpdir,
            },
        )
    return raw_key


def sync_keys(keys_path: Path) -> None:
    """Sync all the keys and refresh the given file"""
    file_lines = []
    with keys_path.open("r") as fkeys:
        for line in fkeys:
            line = line.strip()
            if not line or line.startswith("#"):
                # Keep comments and empty lines
                file_lines.append(line)
                continue

            fields = line.split(" ")
            if len(fields) < 2:
                raise ValueError(f"Unexpected line: {line!r}")
            current_key_id = fields[0]
            email = fields[1]
            raw_key = None
            wkd_url = None
            key_comment = None
            if "@" in email:
                email = email.lower()

                # Download the key using WKD
                wkd_url = get_wkd_advanced_url(email)
                try:
                    with urllib.request.urlopen(wkd_url) as response:
                        raw_key = response.read()
                except urllib.error.URLError:
                    pass
                else:
                    print(f"Downloaded key for {email} from {wkd_url}")
                    key_comment = wkd_url

                # Try the direct method when the advanced one failed
                # Ignore domains which have issues in their configuration
                if raw_key is None and not email.endswith("@att.net"):
                    wkd_url = get_wkd_direct_url(email)
                    raw_key = None
                    try:
                        with urllib.request.urlopen(wkd_url) as response:
                            raw_key = response.read()
                    except urllib.error.URLError:
                        pass
                    else:
                        print(f"Downloaded key for {email} from {wkd_url}")
                        key_comment = wkd_url

            for url in fields[2:]:
                # Check URL, and only keep the first valid key
                with urllib.request.urlopen(url) as response:
                    armored_key = response.read()
                try:
                    new_raw_key = unarmor_gpg(armored_key)
                except ValueError as exc:
                    raise ValueError(f"Error in {url!r}: {exc}")

                if new_raw_key == b"":
                    print(f"Downloaded empty key from {url}")
                    continue
                if raw_key is None:
                    raw_key = new_raw_key
                    key_comment = url
                print(f"Downloaded key from {url}")

            # Try using GnuPG directly
            if raw_key is None:
                raw_key = gpg_recv_key(current_key_id)
                key_comment = "received using GnuPG"

            # Save the key using the key ID
            key_id = get_pgp_key_id(raw_key)
            file_name = email.replace("@", "_").replace("+", "_") + "_" + key_id + ".asc"
            assert re.match(
                r"^[A-Za-z][-0-9A-Za-z._]+$", file_name
            ), f"Unexpected characters in file name {file_name!r}"
            print(f"Saving key for {email!r} in {'all_keys/' + file_name!r}")
            b64_key = base64.b64encode(raw_key).decode("ascii")
            with (ALL_KEYS_PATH / file_name).open("w") as fkey:
                print("-----BEGIN PGP PUBLIC KEY BLOCK-----", file=fkey)
                print(f"Comment: {key_comment}", file=fkey)
                print("", file=fkey)
                for offset in range(0, len(b64_key), 64):
                    print(b64_key[offset:offset + 64], file=fkey)
                print(opgp_crc24_b64(raw_key), file=fkey)
                print("-----END PGP PUBLIC KEY BLOCK-----", file=fkey)

            # Write the key ID in the file
            new_line = f"0x{key_id} {email}"
            if len(fields) > 2:
                new_line += " " + " ".join(fields[2:])
            file_lines.append(new_line)

    # Refresh the file
    with keys_path.open("w") as fout:
        print("\n".join(file_lines), file=fout)


if __name__ == "__main__":
    self_check()
    sync_keys(KEYS_PATH)
