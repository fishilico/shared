#!/usr/bin/env python3
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
"""Decode a KeePass database (.kdb or .kdbx)

Documentation:

* https://keepass.info/help/kb/kdbx_4.html
  KDBX 4 format

* https://github.com/libkeepass/pykeepass
  Python library to interact with keepass databases (supports KDBX3 and KDBX4)

* http://web.archive.org/web/20160229111603/http://blog.sharedmemory.fr/en/2014/04/30/keepass-file-format-explained/
  KeePass file format explained
  available on https://gist.github.com/lgg/e6ccc6e212d18dd2ecd8a8c116fb1e45
"""
import argparse
import base64
import binascii
import collections
import gzip
import hashlib
import hmac
from pathlib import Path
import re
import struct
import sys
import xml.dom.minidom  # noqa

import Cryptodome.Cipher.AES

try:
    from Cryptodome.Cipher import ChaCha20
except ImportError:
    # On Ubuntu, python3-pycryptodome installs in Cryptodome module
    from Cryptodome.Cipher import ChaCha20
    from Cryptodome.Cipher import Salsa20
else:
    from Cryptodome.Cipher import Salsa20


try:
    import argon2
    has_argon2 = True
except ImportError:
    sys.stderr.write("Warning: argon2 fails to load. Proceeding without it\n")
    has_argon2 = False


KDB1_SIGNATURE = 0xb54bfb65
KDB2PRE_SIGNATURE = 0xb54bfb66
KDB2_SIGNATURE = 0xb54bfb67

AES_KDF_UUID = b'\xc9\xd9\xf3\x9a\x62\x8a\x44\x60\xbf\x74\x0d\x08\xc1\x8a\x4f\xea'
ARGON2_KDF_UUID = b'\xef\x63\x6d\xdf\x8c\x29\x44\x4b\x91\xf7\xa9\xa4\x03\xe3\x0a\x0c'

AES_UUID = b'\x31\xc1\xf2\xe6\xbf\x71\x43\x50\xbe\x58\x05\x21\x6a\xfc\x5a\xff'
CHACHA20_UUID = b'\xd6\x03\x8a\x2b\x8b\x6f\x4c\xb5\xa5\x24\x33\x9a\x31\xdb\xb5\x9a'

SALSA20_NONCE = b'\xe8\x30\x09\x4b\x97\x20\x5d\x2a'


def xx(data):
    """One-line hexadecimal representation of binary data"""
    if sys.version_info < (3, 5):
        return binascii.hexlify(data).decode('ascii')
    return data.hex()


class KeePassDB:
    """Hold information about a KeePass database"""
    def __init__(self, db_path):
        self.xml_data = None
        self.xml_dom = None
        self.inner_random_stream_id = None
        self.inner_random_stream_key = None

        with db_path.open('rb') as stream:
            data = stream.read()
        # Decode header
        self.signature1, self.signature2 = struct.unpack('<II', data[:8])
        if self.signature1 != 0x9aa2d903:
            raise ValueError("Invalid file signature: {:#x}".format(self.signature1))
        if self.signature2 == KDB1_SIGNATURE:
            raise NotImplementedError("KeePass 1.x .kdb format not yet implemented")
        if self.signature2 == KDB2PRE_SIGNATURE:
            raise NotImplementedError("KeePass 2.x pre-release format not yet implemented")
        if self.signature2 == KDB2_SIGNATURE:
            self.load_kdbx(data, 8)
            return
        raise ValueError("Invalid file format signature: {:#x}".format(self.signature2))

    def load_kdbx(self, data, offset):
        """Load .kdbx data"""
        self.version_minor, self.version_major = struct.unpack('<HH', data[offset:offset + 4])
        offset += 4
        print("KDBX version {}.{}".format(self.version_major, self.version_minor))
        if (self.version_major, self.version_minor) not in ((3, 1), (4, 0)):
            print("Warning: this version may use unimplemented features")

        # Parse TLV fields
        print("Header:")
        while True:
            if self.version_major >= 4:
                field_type, field_len = struct.unpack('<BI', data[offset:offset + 5])
                offset += 5
            else:
                field_type, field_len = struct.unpack('<BH', data[offset:offset + 3])
                offset += 3
            if offset + field_len >= len(data):
                raise ValueError("Truncated archive: {} + {} >= {}".format(offset, field_len, len(data)))
            field_value = data[offset:offset + field_len]
            offset += field_len
            if field_type == 0:
                if field_value != b'\r\n\r\n':
                    raise ValueError("Unexpected end of header marker: {}".format(repr(field_value)))
                break

            if field_type == 1:
                print("  * Comment: {}".format(repr(field_value)))
            elif field_type == 2:
                self.cipher_id = field_value
                if field_value == AES_UUID:
                    print("  * Cipher ID: AES")
                elif field_value == CHACHA20_UUID:
                    print("  * Cipher ID: ChaCha20")
                else:
                    raise ValueError("Unexpected cipher ID: {}".format(repr(field_value)))
            elif field_type == 3:
                if field_len != 4:
                    raise ValueError("Unexpected compression flags length: {}".format(field_len))
                self.compression_flags, = struct.unpack('<I', field_value)
                if self.compression_flags == 0:
                    print("  * Compression Flags: None")
                elif self.compression_flags == 1:
                    print("  * Compression Flags: GZip")
                else:
                    raise ValueError("Unexpected compression flags: {:#x}".format(self.compression_flags))
            elif field_type == 4:
                self.master_seed = field_value
                print("  * Master Seed [{}]: {}".format(field_len, xx(field_value)))
            elif field_type == 5:
                self.tranform_seed = field_value
                print("  * AES-KDF Transform Seed [{}]: {}".format(field_len, xx(field_value)))
            elif field_type == 6:
                if field_len != 8:
                    raise ValueError("Unexpected transform rounds length: {}".format(field_len))
                self.transform_rounds, = struct.unpack('<Q', field_value)
                print("  * AES-KDF Transform Rounds: {}".format(self.transform_rounds))
            elif field_type == 7:
                self.encryption_iv = field_value
                print("  * Encryption IV [{}]: {}".format(field_len, xx(field_value)))
            elif field_type == 8:
                self.inner_random_stream_key = field_value
                print("  * Protected stream key [{}]: {}".format(field_len, xx(field_value)))
            elif field_type == 9:
                self.stream_start_bytes = field_value
                print("  * Stream start bytes [{}]: {}".format(field_len, xx(field_value)))
            elif field_type == 10:
                if field_len != 4:
                    raise ValueError("Unexpected inner random stream ID length: {}".format(field_len))
                self.inner_random_stream_id, = struct.unpack('<I', field_value)
                if self.inner_random_stream_id == 0:
                    print("  * Inner random stream ID: nothing")
                elif self.inner_random_stream_id == 1:
                    print("  * Inner random stream ID: ARC4")
                elif self.inner_random_stream_id == 2:
                    print("  * Inner random stream ID: Salsa20")
                else:
                    raise ValueError("Unexpected inner random stream ID: {:#x}".format(self.inner_random_stream_id))
            elif field_type == 11:
                # Introduced in KDBX 4
                self.kdf_paramaters = self.decode_variant_dict(field_value)
                if '$UUID' not in self.kdf_paramaters:
                    raise ValueError("Missing KDF UUID: {}".format(repr(self.kdf_paramaters.items())))
                kdf_uuid = self.kdf_paramaters['$UUID']

                print("  * KDF parameters:")
                for key, value in self.kdf_paramaters.items():
                    value_desc = '?'
                    if key == '$UUID':
                        if value == AES_KDF_UUID:
                            value_desc = 'AES KDF'
                        elif value == ARGON2_KDF_UUID:
                            value_desc = 'Argon2 KDF'
                        else:
                            raise ValueError("Unexpected KDF UUID: {}".format(xx(value)))
                    elif kdf_uuid == AES_KDF_UUID:
                        if key == 'R':
                            value_desc = 'Rounds'
                        elif key == 'S':
                            value_desc = 'Seed'
                    elif kdf_uuid == ARGON2_KDF_UUID:
                        if key == 'A':
                            value_desc = 'Associated Data'
                        elif key == 'I':
                            value_desc = 'Iterations'
                        elif key == 'K':
                            value_desc = 'Secret Key'
                        elif key == 'M':
                            value_desc = 'Memory'
                        elif key == 'S':
                            value_desc = 'Salt'
                        elif key == 'P':
                            value_desc = 'Parallelism'
                        elif key == 'V':
                            value_desc = 'Version'

                    if isinstance(value, bytes):
                        print("    - {} [{}]: {} ({})".format(key, len(value), xx(value), value_desc))
                    else:
                        print("    - {} = {} ({})".format(key, repr(value), value_desc))
            elif field_type == 12:
                # Introduced in KDBX 4
                self.plugin_headers = self.decode_variant_dict(field_value)
                print("  * Plugin-provided headers:")
                for key, value in self.plugin_headers.items():
                    if isinstance(value, bytes):
                        print("    - {} [{}]: {}".format(key, len(value), xx(value)))
                    else:
                        print("    - {} = {}".format(key, repr(value)))
            else:
                print("  * Type {} unknown [{}]: {}".format(field_type, field_len, repr(field_value)))

        self.header_bytes = data[:offset]

        if self.version_major == 4:
            computed_header_digest = hashlib.sha256(self.header_bytes).digest()
            self.header_digest = data[offset:offset + 32]
            offset += 32
            self.header_hmac = data[offset:offset + 32]
            offset += 32
            print("  * Header SHA256 digest: {}".format(xx(self.header_digest)))
            print("  * Header HMAC-SHA256: {}".format(xx(self.header_hmac)))
            if self.header_digest != computed_header_digest:
                raise ValueError("Corrupted header: mismatched SHA256 {} != {}".format(
                    xx(self.header_digest), xx(computed_header_digest)))

        print("Encrypted data: {:#x} bytes from offset {:#x}".format(len(data) - offset, offset))
        self.encrypted_data = data[offset:]

    @staticmethod
    def decode_variant_dict(data):
        """Decode a VariantDictionary object from KDBX 4 database"""
        version, = struct.unpack('<H', data[:2])
        if version != 0x100:
            raise NotImplementedError("VariantDictionary version {:#x} not yet implemented".format(version))
        offset = 2
        result = collections.OrderedDict()
        while True:
            value_type, = struct.unpack('B', data[offset:offset + 1])
            offset += 1
            if value_type == 0:
                break
            keylen, = struct.unpack('<I', data[offset:offset + 4])
            offset += 4
            # key is specified as: string, UTF-8, without BOM, without null terminator
            key = data[offset:offset + keylen].decode()
            offset += keylen
            value_len, = struct.unpack('<I', data[offset:offset + 4])
            offset += 4
            value_bytes = data[offset:offset + value_len]
            offset += value_len

            if key in result:
                print("Warning: duplicated key {} in VariantDictionary".format(repr(key)))

            # Decode the value
            if value_type == 0x04 and value_len == 4:  # UInt32
                value, = struct.unpack('<I', value_bytes)
            elif value_type == 0x05 and value_len == 8:  # UInt64
                value, = struct.unpack('<Q', value_bytes)
            elif value_type == 0x08 and value_bytes in (b'\0', b'\x01'):  # Bool
                value = (value_bytes != b'\0')
            elif value_type == 0x0c and value_len == 4:  # Int32
                value, = struct.unpack('<i', value_bytes)
            elif value_type == 0x0d and value_len == 8:  # Int64
                value, = struct.unpack('<q', value_bytes)
            elif value_type == 0x18:  # String
                value = value_bytes.decode()
            elif value_type == 0x42:  # Byte array
                value = value_bytes
            else:
                raise NotImplementedError("VariantDictionary type {:#x} not yet implemented (value {})".format(
                    value_type, repr(value_bytes)))
            result[key] = value

        if offset != len(data):
            raise ValueError("Unexpected Null terminator in VariantDictionary: {:#x} != {:#x}".format(
                offset, len(data)))
        return result

    def decrypt(self, passphrase, keyfile):
        """Decrypt the database using a passphrase and/or a keyfile"""
        if self.version_major == 4:
            self.decrypt_kdbx4(passphrase, keyfile)
        elif self.version_major == 3:
            self.decrypt_kdbx3(passphrase, keyfile)
        else:
            raise NotImplementedError("File format (version {}.{}) not yet implemented".format(
                self.version_major, self.version_minor))

    @staticmethod
    def get_composite_key(passphrase, keyfile):
        """Get the composite key associated with the passphrase and the keyfile"""
        hashes = b''
        if passphrase is not None:
            hashes += hashlib.sha256(passphrase.encode()).digest()
        if keyfile is not None:
            with keyfile.open('rb') as stream:
                hash_ctx = hashlib.sha256()
                while True:
                    data = stream.read(4096)
                    if not data:
                        break
                    hash_ctx.update(data)
                hashes += hash_ctx.digest()
        # Compute the composite key by hashing the key material again
        return hashlib.sha256(hashes).digest()

    @staticmethod
    def aes_kdf(composite_key, seed, rounds):
        """Derive a transformed key using AES KDF"""
        aes = Cryptodome.Cipher.AES.new(seed, Cryptodome.Cipher.AES.MODE_ECB)
        transformed_key = composite_key
        for _ in range(rounds):
            transformed_key = aes.encrypt(transformed_key)
        return hashlib.sha256(transformed_key).digest()

    def get_decryptor(self, master_key):
        """Get a function that implements decryption, using the computed master key"""
        if self.cipher_id == AES_UUID:
            aes_key = hashlib.sha256(master_key).digest()
            cipher = Cryptodome.Cipher.AES.new(aes_key, Cryptodome.Cipher.AES.MODE_CBC, self.encryption_iv)
            return cipher.decrypt

        if self.cipher_id == CHACHA20_UUID:
            chacha20_key = hashlib.sha256(master_key).digest()
            cipher = ChaCha20.new(key=chacha20_key, nonce=self.encryption_iv)
            return cipher.decrypt

        raise NotImplementedError("Cipher with ID {} is not yet implemented".format(self.cipher_id))

    def remove_encryption_padding(self, data):
        """Remove PKCS#5 padding from AES-CBC encryption plaintext"""
        if self.cipher_id == AES_UUID:
            # Check PKCS#5 padding
            padlen, = struct.unpack('B', data[-1:])
            if not (1 <= padlen <= 0x10) or any(x != data[-1] for x in data[-padlen:]):
                raise ValueError("Wrong PKCS#5 padding")
            return data[:-padlen]
        return data

    def decrypt_kdbx3(self, passphrase, keyfile):
        """Decrypt the .kdbx database in KDBX 3 using a passphrase and/or a keyfile"""
        print("Decrypting a KDBX3 database")
        composite_key = self.get_composite_key(passphrase, keyfile)
        print("* Computed composite key: {}".format(xx(composite_key)))

        # Compute the master key using AES-KDF
        transformed_key = self.aes_kdf(composite_key, self.tranform_seed, self.transform_rounds)
        print("* Computed transformed key: {}".format(xx(transformed_key)))
        master_key = self.master_seed + transformed_key

        # Decrypt the data using the master key
        decryptor = self.get_decryptor(master_key)
        data = decryptor(self.encrypted_data)
        data = self.remove_encryption_padding(data)

        print("* Decrypted start bytes: {}".format(data[:len(self.stream_start_bytes)]))
        if data[:len(self.stream_start_bytes)] != self.stream_start_bytes:
            raise ValueError("Start bytes were different. Wrong secret!")

        # Parse blocks
        offset = len(self.stream_start_bytes)
        all_blocks = []
        while offset < len(data):
            block_id, = struct.unpack('<I', data[offset:offset + 4])
            block_hash = data[offset + 4:offset + 0x24]
            block_size, = struct.unpack('<I', data[offset + 0x24:offset + 0x28])
            offset += 0x28

            if not block_size:
                continue

            if offset + block_size > len(data):
                raise ValueError("Truncated archive: {} + {} > {}".format(offset, block_size, len(data)))
            block_data = data[offset:offset + block_size]
            offset += block_size

            if hashlib.sha256(block_data).digest() != block_hash:
                raise ValueError("Mismatched block digest for block {}".format(block_id))
            all_blocks.append(block_data)

        data = b''.join(all_blocks)
        if self.compression_flags == 1:
            data = gzip.decompress(data)

        print("XML Data: {} bytes".format(len(data)))
        self.xml_data = data.decode()
        self.xml_dom = xml.dom.minidom.parseString(self.xml_data)

    def decrypt_kdbx4(self, passphrase, keyfile):
        """Decrypt the .kdbx database in KDBX 4 using a passphrase and/or a keyfile"""
        print("Decrypting a KDBX4 database")
        composite_key = self.get_composite_key(passphrase, keyfile)
        print("* Computed composite key: {}".format(xx(composite_key)))

        # Compute the master key
        if self.kdf_paramaters['$UUID'] == AES_KDF_UUID:
            transformed_key = self.aes_kdf(
                composite_key,
                self.kdf_paramaters['S'],
                self.kdf_paramaters['R'],
            )
        elif self.kdf_paramaters['$UUID'] == ARGON2_KDF_UUID:
            if not has_argon2:
                raise RuntimeError("argon2 module is required in order to decrypt this database")
            transformed_key = argon2.low_level.hash_secret_raw(
                secret=composite_key,
                salt=self.kdf_paramaters['S'],
                time_cost=self.kdf_paramaters['I'],
                memory_cost=self.kdf_paramaters['M'] // 1024,
                parallelism=self.kdf_paramaters['P'],
                hash_len=32,
                type=argon2.Type.D,
                version=self.kdf_paramaters['V'],
            )
        else:
            raise ValueError("Unexpected KDF UUID {}".format(repr(self.kdf_paramaters['$UUID'])))
        print("* Computed transformed key: {}".format(xx(transformed_key)))

        assert len(self.master_seed) == 32
        assert len(transformed_key) == 32

        # Derive the transformed key into the master key and the HMAC key
        master_key = self.master_seed + transformed_key
        hmac_key = hashlib.sha512(master_key + b'\x01').digest()

        # Verify the header HMAC
        header_block_key = hashlib.sha512(b'\xff\xff\xff\xff\xff\xff\xff\xff' + hmac_key).digest()
        header_hmac = hmac.new(header_block_key, self.header_bytes, hashlib.sha256).digest()
        if self.header_hmac != header_hmac:
            raise ValueError("Corrupted header: mismatched HMAC-SHA256 {} != {}".format(
                xx(self.header_hmac), xx(header_hmac)))

        # Prepare ciphers using the master key
        decryptor = self.get_decryptor(master_key)

        # Parse blocks of encrypted data, prefixed by HMAC
        data = self.encrypted_data
        offset = 0
        all_blocks = []
        block_id = 0
        while offset < len(data):
            block_hmac = data[offset:offset + 0x20]
            block_size, = struct.unpack('<I', data[offset + 0x20:offset + 0x24])
            offset += 0x24

            if not block_size:
                continue

            if offset + block_size > len(data):
                raise ValueError("Truncated archive: {} + {} > {}".format(offset, block_size, len(data)))
            encrypted_block_data = data[offset:offset + block_size]
            offset += block_size

            # Verify the block HMAC
            block_hmac_key = hashlib.sha512(struct.pack('<Q', block_id) + hmac_key).digest()
            hmac_ctx = hmac.new(block_hmac_key, None, hashlib.sha256)
            hmac_ctx.update(struct.pack('<Q', block_id))
            hmac_ctx.update(struct.pack('<I', len(encrypted_block_data)))
            hmac_ctx.update(encrypted_block_data)
            if hmac_ctx.digest() != block_hmac:
                raise ValueError("Mismatched block HMAC")

            # Decrypt the block
            block_data = decryptor(encrypted_block_data)
            block_data = self.remove_encryption_padding(block_data)
            all_blocks.append(block_data)
            block_id += 1

        data = b''.join(all_blocks)
        # Decompress the data
        if self.compression_flags == 1:
            data = gzip.decompress(data)

        # Parse the inner header
        print("Inner Header:")
        offset = 0
        while True:
            field_type, field_len = struct.unpack('<BI', data[offset:offset + 5])
            offset += 5
            if offset + field_len >= len(data):
                raise ValueError("Truncated archive: {} + {} >= {}".format(offset, field_len, len(data)))
            field_value = data[offset:offset + field_len]
            offset += field_len
            if field_type == 0:
                if field_value != b'':
                    raise ValueError("Unexpected end of header marker: {}".format(repr(field_value)))
                break
            if field_type == 1:
                if field_len != 4:
                    raise ValueError("Unexpected inner random stream ID length: {}".format(field_len))
                self.inner_random_stream_id, = struct.unpack('<I', field_value)
                if self.inner_random_stream_id == 0:
                    print("  * Inner random stream ID: nothing")
                elif self.inner_random_stream_id == 1:
                    print("  * Inner random stream ID: ARC4")
                elif self.inner_random_stream_id == 2:
                    print("  * Inner random stream ID: Salsa20")
                elif self.inner_random_stream_id == 3:
                    print("  * Inner random stream ID: ChaCha20")
            elif field_type == 2:
                self.inner_random_stream_key = field_value
                print("  * Inner random stream key [{}]: {}".format(field_len, xx(field_value)))
            elif field_type == 3:
                print("  * Binary (entry attachment) [{}]: {}".format(field_len, xx(field_value)))
            else:
                print("  * Type {} unknown [{}]: {}".format(field_type, field_len, repr(field_value)))

        # The remaining data is in XML
        data = data[offset:]
        print("XML Data: {} bytes".format(len(data)))
        self.xml_data = data.decode()
        self.xml_dom = xml.dom.minidom.parseString(self.xml_data)

    def unprotect_passwords(self):
        """Unprotect the password fields in the database"""
        if self.inner_random_stream_id == 2:
            # Decrypt Salsa20-protected data
            key = hashlib.sha256(self.inner_random_stream_key).digest()
            cipher = Salsa20.new(key, SALSA20_NONCE)
        elif self.inner_random_stream_id == 3:
            # Decrypt ChaCha20-protected data
            key_hash = hashlib.sha512(self.inner_random_stream_key).digest()
            cipher = ChaCha20.new(key=key_hash[:32], nonce=key_hash[32:44])
        else:
            raise NotImplementedError("Inner random stream variant {} not yet implemented".format(
                self.inner_random_stream_id))

        # Perform like the XPath query //Value[@Protected='True']
        for value_elem in self.xml_dom.getElementsByTagName('Value'):
            if value_elem.firstChild is None:
                # Empty passwords are skipped
                continue
            protected_attr = value_elem.getAttribute('Protected')
            if not protected_attr:
                continue
            if protected_attr != 'True':
                raise ValueError("Unexpected Value/Protected attribute value: {}".format(
                    repr(protected_attr)))
            protected_data_b64 = value_elem.firstChild.data.strip()
            protected_data = base64.b64decode(protected_data_b64)
            plain_text_bin = cipher.decrypt(protected_data)
            plain_text = plain_text_bin.decode(errors='replace')
            value_elem.firstChild.data = plain_text
            value_elem.setAttribute('Protected', 'Decrypted')


def main(argv=None):
    parser = argparse.ArgumentParser(description="Decode a KeePass database")
    parser.add_argument('database', metavar="KDB", type=Path,
                        help="path to KeePass database (.kdb or .kdbx)")
    parser.add_argument('-p', '--passphrase', type=str,
                        help="DB passphrase")
    parser.add_argument('-k', '--keyfile', type=Path,
                        help="DB keyfile")
    args = parser.parse_args(argv)

    kdb = KeePassDB(args.database)

    if args.passphrase or args.keyfile:
        kdb.decrypt(args.passphrase, args.keyfile)
        kdb.unprotect_passwords()
        xml_pretty = kdb.xml_dom.toprettyxml(indent="  ")
        # Remove blank lines
        xml_pretty = re.sub(r'\n\s*\n', '\n', xml_pretty).strip()
        print(xml_pretty)


if __name__ == '__main__':
    main()
