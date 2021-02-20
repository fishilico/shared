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
"""Parse Java KeyStore (JKS) and Java Cryptography Extension KeyStore (JCEKS) files

Usage in order to export all private keys and certificates in PEM format,
from a keystore located in store.jks with password changeit:

    ./parse_jceks.py store.jks -p changeit -P | sed -n '/-----BEGIN/,/-----END/p'


https://wp.internetsociety.org/ndss/wp-content/uploads/sites/25/2018/02/ndss2018_02B-1_Focardi_paper.pdf
    JKS: Java KeyStore (JKS) is the first official implementation of a keystore
        that appeared in Java since the release of JDK 1.2
    JCEKS: Java Cryptography Extension KeyStore (JCEKS) has been introduced
        after the release of JDK 1.2 in the external Java Cryptography Extension
        (JCE) package and merged later into the standard JDK distribution from
        version 1.4.

Related projects:
* https://github.com/kurtbrose/pyjks
  a pure python Java KeyStore file parser, including private key decryption
"""
import argparse
import datetime
import hashlib
import json
import logging
import os.path
import struct
import sys
import tempfile

import Crypto.Cipher.DES3

import util_asn1
from util_bin import run_openssl_show_cert, run_process_with_input, xx
from util_crypto import report_if_missing_cryptography, describe_der_certificate


logger = logging.getLogger(__name__)


# Magic numbers to identify files
MAGIC_NUMBER_JKS = b'\xfe\xed\xfe\xed'
MAGIC_NUMBER_JCEKS = b'\xce\xce\xce\xce'


def PBEWithMD5AndDES_derivation(password, salt, iterations):
    """Compute a key and iv from a password and salt according to PBEWithMD5AndDES"""
    assert len(salt) == 8
    last_value = password.encode('ascii') + salt
    for _ in range(iterations):
        last_value = hashlib.md5(last_value).digest()
    assert len(last_value) == 16
    key = last_value[:8]
    iv = last_value[8:]
    return key, iv


def PBEWithMD5AndTripleDES_derivation(password, salt, iterations):
    """Compute a key and iv from a password and salt according to PBEWithMD5AndTripleDES"""
    # Derivate the key and iv from the password and salt, in a weird way
    assert len(salt) == 8
    salt_halves = [salt[:4], salt[4:]]
    if salt_halves[0] == salt_halves[1]:
        # Invert the first half of the salt, with a typo in the algorithm
        # for (i=0; i<2; i++) {
        #     byte tmp = salt[i];
        #     salt[i] = salt[3-i];
        #     salt[3-1] = tmp; // <-- typo '1' instead of 'i'
        # }
        s0, s1, s2, s3 = struct.unpack('BBBB', salt_halves[0])
        salt_halves[0] = struct.pack('BBBB', s3, s0, s1, s3)

    password_bytes = password.encode('ascii')
    key_and_iv = b''
    for salt_half in salt_halves:
        last_value = salt_half
        for _ in range(iterations):
            last_value = hashlib.md5(last_value + password_bytes).digest()
        key_and_iv += last_value
    assert len(key_and_iv) == 32
    key = key_and_iv[:24]
    iv = key_and_iv[24:]
    return key, iv


def generate_keystore(store_type, password):
    """Generate a JKS or JCEKS keystore with some content"""
    assert store_type in ('jks', 'jceks')
    temporary_dir = tempfile.mkdtemp(suffix='_java_keystore-test')
    ks_path = os.path.join(temporary_dir, 'store.jks')
    try:
        # By default it generates a DSA keypair
        run_process_with_input(
            [
                'keytool', '-genkeypair', '-noprompt',
                '-keyalg', 'dsa',
                '-storetype', store_type,
                '-keystore', ks_path,
                '-storepass', password,
                '-keypass', password,
                '-alias', 'mykeypair',
                '-dname', 'CN=example',
            ],
            None, fatal=True)
        run_process_with_input(
            [
                'keytool', '-genkeypair', '-noprompt',
                '-keyalg', 'rsa', '-sigalg', 'SHA256withRSA',
                '-storetype', store_type,
                '-keystore', ks_path,
                '-storepass', password,
                '-keypass', password,
                '-alias', 'mykeypair_rsa_sha256sig',
                '-dname', 'CN=example',
            ],
            None, fatal=True)

        # Add a secret key when using jceks
        if store_type == 'jceks':
            # By default it generates a DES key
            run_process_with_input(
                [
                    'keytool', '-genseckey',
                    '-keyalg', 'des',
                    '-storetype', store_type,
                    '-keystore', ks_path,
                    '-storepass', password,
                    '-keypass', password,
                    '-alias', 'mysecret_key',
                ],
                None, fatal=True)
            run_process_with_input(
                [
                    'keytool', '-genseckey',
                    '-keyalg', 'aes', '-keysize', '192',
                    '-storetype', store_type,
                    '-keystore', ks_path,
                    '-storepass', password,
                    '-keypass', password,
                    '-alias', 'mysecret_aes192key',
                ],
                None, fatal=True)

        with open(ks_path, 'rb') as fks:
            ks_content = fks.read()
        if not ks_content:
            raise ValueError("keytool did not produce any output")
        return ks_content
    finally:
        try:
            os.remove(ks_path)
        except OSError as exc:
            # If removing the files failed, the error will appear in rmdir
            logger.debug("Error while removing files: %r", exc)
        os.rmdir(temporary_dir)


def read_prelen_string(data, offset):
    """Read a string prefixed by its length from some data"""
    length, = struct.unpack('>H', data[offset:offset + 2])
    offset += 2
    end_off = offset + length
    if end_off > len(data):
        raise ValueError("String too large: {:#x} + {:#x} > {:#x}".format(offset, length, len(data)))
    return data[offset:end_off].decode('utf-8', 'replace'), end_off


class SerializedJavaObject(object):
    """Deserialize a Java object from the input data"""
    def __init__(self, data, offset=0):
        self.data = data
        self.offset = offset
        self.references = []

        # Header magic and version (\xac\xed\x00\x05)
        magic, version = self.unpack('>HH')
        if magic != 0xaced or version != 5:
            raise ValueError("Unimplemented serialized Java magic {:#x} with version {}".format(magic, version))

        self.obj = self.read_java_ser_opcode()

    def unpack(self, fmt):
        """Unpack integers from the data"""
        size = 0
        for c in fmt:
            if c in 'Bb':
                size += 1
            elif c in 'Hh':
                size += 2
            elif c in 'Ii':
                size += 4
            elif c in 'Qq':
                size += 8
        values = struct.unpack(fmt, self.data[self.offset:self.offset + size])
        self.offset += size
        return values

    def read_string(self):
        """Read a string prefixed by its length"""
        value, self.offset = read_prelen_string(self.data, self.offset)
        return value

    def read_java_value(self, java_type):
        """Read a value described by a java type"""
        if len(java_type) == 1:
            if java_type == 'B':  # byte
                return self.unpack('b')[0]
            if java_type == 'C':  # char
                return self.unpack('b')[0]
            if java_type == 'D':  # double
                return self.unpack('>d')[0]
            if java_type == 'F':  # float
                return self.unpack('>f')[0]
            if java_type == 'I':  # integer
                return self.unpack('>i')[0]
            if java_type == 'J':  # long
                return self.unpack('>q')[0]
            if java_type == 'S':  # short
                return self.unpack('>h')[0]
            if java_type == 'Z':  # boolean
                return self.unpack('b')[0] != 0

        if java_type.startswith('['):
            # Array
            array_obj = self.read_java_ser_opcode()
            if array_obj['java_type'] != 'array':
                raise ValueError("Unexpected {} object when reading an array".format(array_obj['java_type']))
            return array_obj['values']

        if java_type.startswith('L'):
            # Object
            obj = self.read_java_ser_opcode()
            if java_type == 'Ljava/lang/String;':
                # String object
                if obj['java_type'] != 'string':
                    raise ValueError("Unexpected {} object when reading a string".format(obj['java_type']))
                return obj['str']

            return obj

        raise NotImplementedError("Unknown value type {}".format(repr(java_type)))

    def read_java_ser_opcode(self):
        """Read a component from a serialized Java object"""
        opcode, = self.unpack('B')
        if opcode == 0x70:  # Null
            return {'java_type': 'null'}

        if opcode == 0x71:  # Reference
            handle, = self.unpack('>I')
            if 0x7e0000 <= handle < 0x7e0000 + len(self.references):
                return self.references[handle - 0x7e0000]
            raise ValueError("Unable to resolve reference {:#x}".format(handle))

        if opcode == 0x72:  # class description
            class_desc = {'java_type': 'classdesc'}
            class_desc['name'] = self.read_string()
            class_desc['serial_version'], class_desc['new_handle'], class_desc['flags'] = self.unpack('>IIB')
            self.references.append(class_desc)

            fields_count, = self.unpack('>H')
            logger.debug("Read Java class desc for %r", class_desc['name'])
            class_desc['fields'] = []
            for field_index in range(fields_count):
                field_typecode, = self.unpack('B')
                field_name = self.read_string()
                if field_typecode == 0x5b:  # '[' for array
                    field_type = self.read_java_ser_opcode()
                    if field_type['java_type'] != 'string':
                        raise ValueError("Unexpected type of type definition: {}".format(field_type['java_type']))
                    if not field_type['str'].startswith('['):
                        raise ValueError("Unexpected string type of array type definition: {}".format(
                            field_type['str']))
                    field_type = field_type['str']
                elif field_typecode == 0x4c:  # 'L' for object
                    field_type = self.read_java_ser_opcode()
                    if field_type['java_type'] != 'string':
                        raise ValueError("Unexpected type of type definition: {}".format(field_type['java_type']))
                    if not field_type['str'].startswith('L') or not field_type['str'].endswith(';'):
                        raise ValueError("Unexpected string type of object type definition: {}".format(
                            field_type['str']))
                    field_type = field_type['str']
                else:
                    field_type = chr(field_typecode)
                logger.debug("Read field type for %r: %r", field_name, field_type)
                class_desc['fields'].append((field_name, field_type))
            class_desc['class_annocation'] = self.read_java_ser_opcode()
            class_desc['super_classdesc'] = self.read_java_ser_opcode()
            if class_desc['super_classdesc']['java_type'] == 'null':
                class_desc['super_classdesc'] = None
            elif class_desc['super_classdesc']['java_type'] != 'classdesc':
                raise ValueError("A super class desc was not a class desc")
            return class_desc

        if opcode == 0x73:  # object
            obj = {'java_type': 'object'}
            obj['class_desc'] = self.read_java_ser_opcode()
            self.references.append(obj)
            cls_flags = obj['class_desc']['flags']
            is_serializable = ((cls_flags & 0x02) != 0)
            is_write_method = is_serializable and ((cls_flags & 0x01) != 0)
            is_externalizable = ((cls_flags & 0x04) != 0)
            is_block_data = is_externalizable and ((cls_flags & 0x08) != 0)
            is_enum = ((cls_flags & 0x10) != 0)
            logger.debug("Reading object %r (ser=%r, wrm=%r, ext=%r, bkd=%r, enu=%r)",
                         obj['class_desc']['name'],
                         is_serializable,
                         is_write_method,
                         is_externalizable,
                         is_block_data,
                         is_enum)
            obj['fields'] = {}
            if is_serializable:
                # Build a list of fields
                cls_desc = obj['class_desc']
                fields = []
                while cls_desc is not None:
                    fields = cls_desc['fields'] + fields
                    cls_desc = cls_desc['super_classdesc']
                all_names = set(f[0] for f in fields)
                if len(all_names) != len(fields):
                    raise ValueError("Non-unique fields found")
                for field_name, field_type in fields:
                    obj['fields'][field_name] = self.read_java_value(field_type)
                    # logger.debug("Got field %r: %r", field_name, obj['fields'][field_name])
            return obj

        if opcode == 0x74:  # string
            string = {
                'java_type': 'string',
                'str': self.read_string(),
            }
            self.references.append(string)
            return string

        if opcode == 0x75:  # array
            array = {'java_type': 'array'}
            array['class_desc'] = self.read_java_ser_opcode()
            self.references.append(array)

            array_type = array['class_desc']['name']
            if len(array_type) < 2 or not array_type.startswith('['):
                raise ValueError("Not an array type: {}".format(repr(array_type)))
            item_type = array_type[1]

            size, = self.unpack('>I')
            array['values'] = [None] * size
            for idx in range(size):
                if item_type in ('[', 'L'):  # array or object
                    array['values'][idx] = self.read_java_ser_opcode()
                else:
                    array['values'][idx] = self.read_java_value(item_type)
            return array

        if opcode == 0x76:  # class
            cls = {
                'java_type': 'class',
                'class_desc': self.read_java_ser_opcode(),
            }
            self.references.append(cls)
            return cls

        if opcode == 0x77:  # Block data
            size, = self.unpack('B')
            return {
                'java_type': 'block data',
                'data': self.unpack('B' * size),
            }

        if opcode == 0x78:  # End block data
            return {'java_type': 'end block data'}

        # Do not decode opcode 0x79: Reset

        if opcode == 0x7a:  # Block data long
            size, = self.unpack('>I')
            return {
                'java_type': 'block data',
                'data': self.unpack('B' * size),
            }

        # Do not decode opcode 0x7b: Exception
        # Do not decode opcode 0x7c: Long String
        # Do not decode opcode 0x7d: Proxy Class Desc

        if opcode == 0x7e:  # Enum
            enum_obj = {
                'java_type': 'enum',
                'class_desc': self.read_java_ser_opcode(),
            }
            self.references.append(enum_obj)
            cst_name = self.read_java_ser_opcode()
            if cst_name['java_type'] != 'string':
                raise ValueError("Unexpected {} object when reading an enum value name".format(obj['java_type']))
            enum_obj['constant_name'] = cst_name['str']
            return enum_obj

        raise NotImplementedError("Unknown serialized Java opcode {:#x}".format(opcode))


def print_ks_certificate(ks_content, offset=0, show_pem=False, list_only=False):
    """Print a certificate contained in a JKS or a JCEKS"""
    cert_type, offset = read_prelen_string(ks_content, offset)
    cert_size, = struct.unpack('>I', ks_content[offset:offset + 4])
    offset += 4
    cert = ks_content[offset:offset + cert_size]
    offset += cert_size

    description = describe_der_certificate(cert)
    print("  * certificate (type {}, {} bytes){}".format(
        repr(cert_type), len(cert),
        ": {}".format(description) if description else ""))

    if cert_type != 'X.509':
        raise NotImplementedError("Unknown certificate format {}".format(repr(cert_type)))

    run_openssl_show_cert(cert, list_only=list_only, show_pem=show_pem, indent="    ")
    return offset


def print_ks_private_key(ks_content, password, offset=0, show_pem=False, list_only=False):
    """Print a private contained in a JKS or a JCEKS"""
    privkey_size, = struct.unpack('>I', ks_content[offset:offset + 4])
    offset += 4
    privkey = ks_content[offset:offset + privkey_size]
    offset += privkey_size
    print("  * private key ({} bytes)".format(len(privkey)))
    # run_process_with_input(['openssl', 'asn1parse', '-i', '-inform', 'DER'], privkey, fatal=True)

    privkey_type_der, privkey_octetstring_der = util_asn1.decode_sequence(privkey, 2)
    privkey_type_oid_der, privkey_type_params_der = util_asn1.decode_sequence(privkey_type_der)
    privkey_type_oid = util_asn1.decode_oid(privkey_type_oid_der)
    privkey_encrypted = util_asn1.decode_octet_string(privkey_octetstring_der)

    decrypted = None
    if privkey_type_oid == '1.3.6.1.4.1.42.2.17.1.1':
        # OID 1.3.6.1.4.1.42.2.17.1.1 is proprietary JavaSoft algorithm
        # {iso(1) identified-organization(3) dod(6) internet(1) private(4)
        #  enterprise(1) Sun Microsystems (42) products(2) 17 1 1}
        assert privkey_type_params_der == b'\x05\x00'  # NULL in ASN.1 DER notation
        print("    * JKS encryption")
        iv = privkey_encrypted[:20]
        integrity_hash = privkey_encrypted[-20:]
        print("    * IV: {}".format(xx(iv)))
        print("    * SHA1 hash: {}".format(xx(integrity_hash)))

        password_bytes = password.encode('utf-16be')
        keystream = []
        while len(keystream) < len(privkey_encrypted) - 40:
            iv = hashlib.sha1(password_bytes + iv).digest()
            keystream += struct.unpack('20B', iv)

        data_struct_fmt = '{}B'.format(len(privkey_encrypted) - 40)
        enc_data = struct.unpack(data_struct_fmt, privkey_encrypted[20:-20])
        decrypted = struct.pack(data_struct_fmt, *[x ^ k for x, k in zip(enc_data, keystream)])
        computed_hash = hashlib.sha1(password_bytes + decrypted).digest()
        if computed_hash != integrity_hash:
            print("    * wrong password (bad SHA1 hash)")
            decrypted = None

    elif privkey_type_oid == '1.3.6.1.4.1.42.2.19.1':
        # OID 1.3.6.1.4.1.42.2.19.1 is PBE_WITH_MD5_AND_DES3_CBC (JCEKS)
        salt_der, iterations = util_asn1.decode_sequence(privkey_type_params_der, 2)
        salt = util_asn1.decode_octet_string(salt_der)
        print("    * JCEKS encryption")
        print("    * salt ({} bytes): {}".format(len(salt), xx(salt)))
        print("    * iterations: {}".format(iterations))

        key, iv = PBEWithMD5AndTripleDES_derivation(password, salt, iterations)
        crypto_3des = Crypto.Cipher.DES3.new(key, Crypto.Cipher.DES3.MODE_CBC, iv)
        decrypted = crypto_3des.decrypt(privkey_encrypted)
        padlen, = struct.unpack('B', decrypted[-1:])
        # Check PKCS#5 padding
        if not (1 <= padlen <= 0x10) or any(x != decrypted[-1] for x in decrypted[-padlen:]):
            print("    * wrong password (bad PKCS#5 padding)")
            decrypted = None
        else:
            decrypted = decrypted[:-padlen]

    else:
        raise ValueError("Unknown private key with OID {}".format(privkey_type_oid))

    if decrypted:
        print("    (password: {})".format(repr(password)))
        # print("    (key: {})".format(xx(key)))
        # print("    (iv: {})".format(xx(iv)))
        util_asn1.show_pkcs8_private_key_info(decrypted, list_only=list_only, show_pem=show_pem, indent="    ")

    chain_length, = struct.unpack('>I', ks_content[offset:offset + 4])
    offset += 4
    for chain_index in range(chain_length):
        offset = print_ks_certificate(ks_content, offset=offset, show_pem=show_pem, list_only=list_only)
    return offset


def print_jceks_secret_key(ks_content, password, offset=0, list_only=False):
    """Print a secret key contained in a JCEKS"""
    # Deserialize the com.sun.crypto.provider.SealedObjectForKeyProtector object
    java_obj = SerializedJavaObject(ks_content, offset)
    if java_obj.obj['java_type'] != 'object':
        raise ValueError("Not a serialized Java object: {}".format(repr(java_obj.obj['java_type'])))
    if java_obj.obj['class_desc']['name'] != 'com.sun.crypto.provider.SealedObjectForKeyProtector':
        raise ValueError("Unexpected object class: {}".format(repr(java_obj.obj['class_desc']['name'])))

    # Extract the fields of the object
    encoded_params = java_obj.obj['fields']['encodedParams']
    encrypted_content = java_obj.obj['fields']['encryptedContent']
    params_alg = java_obj.obj['fields']['paramsAlg']
    seal_alg = java_obj.obj['fields']['sealAlg']
    if params_alg != 'PBEWithMD5AndTripleDES':
        raise ValueError("Unexpected alg: {}".format(repr(params_alg)))
    if seal_alg != 'PBEWithMD5AndTripleDES':
        raise ValueError("Unexpected seal alg: {}".format(repr(seal_alg)))

    params = struct.pack('b' * len(encoded_params), *encoded_params)
    encrypted = struct.pack('b' * len(encrypted_content), *encrypted_content)

    # The parameters consist in an ASN.1 sequence of [salt, iterations_count]
    print("  * params ({} bytes: {})".format(len(params), xx(params)))
    # run_process_with_input(['openssl', 'asn1parse', '-i', '-inform', 'DER'], params)
    params_asn1 = Crypto.Util.asn1.DerSequence()
    params_asn1.decode(params)
    assert len(params_asn1) == 2
    salt_obj, iterations = params_asn1
    salt_asn1 = Crypto.Util.asn1.DerObject()
    salt_asn1.decode(salt_obj)
    salt = salt_asn1.payload
    print("    * salt ({} bytes): {}".format(len(salt), xx(salt)))
    print("    * iterations: {}".format(iterations))
    if len(salt) != 8:
        raise ValueError("Unexpected salt length: {}".format(len(salt)))

    print("  * encrypted ({} bytes):".format(len(encrypted)))

    key, iv = PBEWithMD5AndTripleDES_derivation(password, salt, iterations)
    crypto_3des = Crypto.Cipher.DES3.new(key, Crypto.Cipher.DES3.MODE_CBC, iv)
    decrypted = crypto_3des.decrypt(encrypted)
    padlen, = struct.unpack('B', decrypted[-1:])
    # Check PKCS#5 padding
    if not (1 <= padlen <= 0x10) or any(x != decrypted[-1] for x in decrypted[-padlen:]):
        print("    * wrong password (pad PKCS#5 padding)")
    else:
        decrypted = decrypted[:-padlen]

        print("    (password: {})".format(repr(password)))
        # print("    (key: {})".format(xx(key)))
        # print("    (iv: {})".format(xx(iv)))

        # Deserialize the plaintext, again
        decrypted_object = SerializedJavaObject(decrypted)
        if decrypted_object.offset != len(decrypted):
            raise ValueError("Stray data after deserialization of encrypted object")
        if decrypted_object.obj['java_type'] != 'object':
            raise ValueError("Not a serialized Java object: {}".format(repr(decrypted_object.obj['java_type'])))

        dec_class_name = decrypted_object.obj['class_desc']['name']
        print("    * Java class: {}".format(repr(dec_class_name)))

        if dec_class_name == 'java.security.KeyRep':
            dec_algorithm = decrypted_object.obj['fields']['algorithm']
            dec_encoded = decrypted_object.obj['fields']['encoded']
            dec_format = decrypted_object.obj['fields']['format']
            dec_type = decrypted_object.obj['fields']['type']['constant_name']

            value = struct.pack('b' * len(dec_encoded), *dec_encoded)
            print("    * algorithm: {}".format(repr(dec_algorithm)))
            print("    * format: {}".format(repr(dec_format)))
            print("    * type: {}".format(repr(dec_type)))
            if list_only:
                print("    * value: {} bytes ({} bits)".format(len(value), 8 * len(value)))
            else:
                print("    * value ({} bytes): {}".format(len(value), xx(value)))
                print("      * repr: {}".format(repr(value)))
        elif dec_class_name == 'javax.crypto.spec.SecretKeySpec':
            dec_algorithm = decrypted_object.obj['fields']['algorithm']
            dec_key = decrypted_object.obj['fields']['key']
            key_value = struct.pack('b' * len(dec_key), *dec_key)
            print("    * algorithm: {}".format(repr(dec_algorithm)))
            if list_only:
                print("    * key: {} bytes ({} bits)".format(len(key_value), 8 * len(key_value)))
            else:
                print("    * key ({} bytes): {}".format(len(key_value), xx(key_value)))
                print("      * repr: {}".format(repr(key_value)))
        else:
            print("Unknown decrypted object, here is a dump:")
            print(json.dumps(decrypted_object.obj))
            raise ValueError("Unexpected object class: {}".format(repr(decrypted_object.obj['class_desc']['name'])))

    # Return the new offset, after the Java object
    return java_obj.offset


def print_keystore(ks_content, password, show_pem=False, list_only=False):
    """Parse a Java KeyStore file and print it"""
    # Header: magic, version, number of aliases
    if ks_content.startswith(MAGIC_NUMBER_JKS):
        store_type = 'jks'
    elif ks_content.startswith(MAGIC_NUMBER_JCEKS):
        store_type = 'jceks'
    else:
        raise ValueError("Not a JKS not a JCEKS")

    version, count = struct.unpack('>II', ks_content[4:0xc])
    if version != 2:
        raise ValueError("Version {} not implemented".format(version))
    print("Keystore (type {}) has {} {}".format(store_type, count, "entries" if count >= 2 else "entry"))

    # Check the password with the integrity hash
    integrity_hash = ks_content[-20:]
    computed_hash = hashlib.sha1(password.encode('utf-16be') + b'Mighty Aphrodite' + ks_content[:-20]).digest()
    if computed_hash == integrity_hash:
        print("* password: {} (integrity hash {})".format(repr(password), xx(integrity_hash)))
    else:
        print("* incorrect password (integrity hash {})".format(xx(integrity_hash)))

    offset = 0xc
    for entry_index in range(count):
        tag, alias_len = struct.unpack('>IH', ks_content[offset:offset + 6])
        offset += 6
        alias = ks_content[offset:offset + alias_len].decode('utf-8', 'replace')
        offset += alias_len
        timestamp, = struct.unpack('>Q', ks_content[offset:offset + 8])
        offset += 8

        timedesc = str(datetime.datetime.fromtimestamp(timestamp / 1000))

        if tag == 1:
            print("[{}] private key {} ({}):".format(entry_index + 1, repr(alias), timedesc))
            offset = print_ks_private_key(ks_content, password, offset=offset, show_pem=show_pem, list_only=list_only)
        elif tag == 2:
            print("[{}] trusted key {} ({}):".format(entry_index + 1, repr(alias), timedesc))
            offset = print_ks_certificate(ks_content, offset=offset, show_pem=show_pem, list_only=list_only)
        elif tag == 3 and store_type == 'jceks':
            print("[{}] secret key {} ({}):".format(entry_index + 1, repr(alias), timedesc))
            offset = print_jceks_secret_key(ks_content, password, offset=offset, list_only=list_only)
        else:
            raise ValueError("Unknown entry tag {}".format(tag))

    if offset + 20 != len(ks_content):
        logger.warning("There remains %d bytes before the integrity hash", len(ks_content) - offset - 20)


def main(argv=None):
    """Program entry point"""
    parser = argparse.ArgumentParser(
        description="Parse a JKS or JCEKS file",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('input', metavar='KEYSTORE', nargs='?', type=str,
                        help="load a keystore instead of generating one")
    parser.add_argument('-t', '--storetype',
                        choices=('jks', 'jceks'), default='jceks',
                        help="type of store to generate")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-p', '--password', type=str, default='changeit',
                        help="keystore password")
    parser.add_argument('-l', '--list', action='store_true',
                        help="list only, without printing the data")
    parser.add_argument('-P', '--pem', action='store_true',
                        help="show certificates and private keys in PEM format")

    args = parser.parse_args(argv)
    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    report_if_missing_cryptography()

    if args.input:
        with open(args.input, 'rb') as fin:
            ks_content = fin.read()
        logger.debug("Parsing file %r (%d bytes)", args.input, len(ks_content))
    else:
        try:
            ks_content = generate_keystore(args.storetype, args.password)
        except ValueError as exc:
            logger.fatal("Generating a keystore failed: %s", exc)
            return 1
        logger.debug("Parsing keystore (%d bytes)", len(ks_content))

    try:
        print_keystore(ks_content, args.password, show_pem=args.pem, list_only=args.list)
    except ValueError as exc:
        logger.fatal("Parsing the keystore failed: %s", exc)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
