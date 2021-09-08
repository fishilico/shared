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
"""Some functions helpful to decode ASN.1 structures"""
import binascii
import logging
import struct

import Cryptodome.Util.asn1

import util_bin


logger = logging.getLogger(__name__)


def decode_object(der_obj):
    """Decode an ASN.1 object in DER format"""
    obj_asn1 = Cryptodome.Util.asn1.DerObject()
    try:
        obj_asn1.decode(der_obj)
    except ValueError as exc:
        logger.error("Unable to decode an ASN.1 object: %s", exc)
        raise
    return obj_asn1.payload


def decode_sequence(der_seq, count=None, counts=None):
    """Decode an ASN.1 sequence in DER format"""
    seq_asn1 = Cryptodome.Util.asn1.DerSequence()
    try:
        seq_asn1.decode(der_seq)
    except ValueError as exc:
        logger.error("Unable to decode an ASN.1 sequence: %s", exc)
        raise
    if count is not None and len(seq_asn1) != count:
        raise ValueError("Unexpected number of items in ASN.1 sequence: {} != {}".format(len(seq_asn1), count))
    if counts is not None and len(seq_asn1) not in counts:
        raise ValueError("Unexpected number of items in ASN.1 sequence: {} not in {}".format(len(seq_asn1), counts))
    return seq_asn1[:]


def decode_set(der_set):
    """Decode an ASN.1 set in DER format"""
    try:
        set_asn1 = Cryptodome.Util.asn1.DerSetOf()
    except AttributeError:
        # PyCrypto < 2.7 did not implement DerSetOf
        raise NotImplementedError("Cryptodome.Util.asn1.DerSetOf is not available")
    try:
        set_asn1.decode(der_set)
    except ValueError as exc:
        logger.error("Unable to decode an ASN.1 set: %s", exc)
        raise
    return set_asn1[:]


def decode_octet_string(der_octet_string):
    """Decode an ASN.1 Octet String in DER format"""
    octet_string_asn1 = Cryptodome.Util.asn1.DerOctetString()
    try:
        octet_string_asn1.decode(der_octet_string)
    except ValueError as exc:
        logger.error("Unable to decode an ASN.1 octet string: %s", exc)
        raise
    except TypeError:
        # python-crypto 2.6.1-4ubuntu0.3 is buggy on Ubuntu 14.04
        octet_string_asn1 = Cryptodome.Util.asn1.DerObject()
        octet_string_asn1.decode(der_octet_string)
    return octet_string_asn1.payload


def decode_unicode_string(der_unicode_string):
    """Decode an ASN.1 Unicode String in DER format"""
    unicode_string = decode_object(der_unicode_string)
    return unicode_string.decode('utf-16be')


def decode_any_string(der_string):
    """Decode an ASN.1 Octet String or BMPSTRING (= Unicode String)"""
    asn1_tag_id, = struct.unpack('B', der_string[:1])
    if asn1_tag_id == 0x04:  # OCTET STRING
        return decode_octet_string(der_string).decode('ascii')
    if asn1_tag_id == 0x1e:  # BMPSTRING
        return decode_unicode_string(der_string)
    raise ValueError("Unable to decode an ASN.1 string with tag {:#x}".format(asn1_tag_id))


def decode_oid(der_objectid):
    """Decode an ASN.1 Object ID in DER format"""
    oid_asn1 = Cryptodome.Util.asn1.DerObjectId()
    try:
        oid_asn1.decode(der_objectid)
    except ValueError as exc:
        logger.error("Unable to decode an ASN.1 object ID: %s (for %s)", exc, util_bin.xx(der_objectid))
        raise
    except TypeError:
        # python-crypto 2.6.1-4ubuntu0.3 is buggy on Ubuntu 14.04:
        #   File "/usr/lib/python2.7/dist-packages/Crypto/Util/asn1.py", line 274, in decode
        #     p = DerObject.decode(derEle, noLeftOvers)
        # TypeError: unbound method decode() must be called with DerObject instance as first argument
        #   (got str instance instead)
        # ... so fallback to a raw DerObject()
        oid_asn1 = Cryptodome.Util.asn1.DerObject()
        oid_asn1.decode(der_objectid)

    # PyCrypto < 2.7 did not decode the Object Identifier. Let's implement OID decoding
    components = []
    current_val = 0
    for idx, byteval in enumerate(struct.unpack('B' * len(oid_asn1.payload), oid_asn1.payload)):
        if idx == 0:
            # The first byte combine the first two digits
            components += [str(v) for v in divmod(byteval, 40)]
        else:
            # 7-bit encoding of variable-length integers with most-significant bit as continuation indicator
            current_val = (current_val << 7) | (byteval & 0x7f)
            if not (byteval & 0x80):
                components.append(str(current_val))
                current_val = 0
    oid_value = '.'.join(components)
    if hasattr(oid_asn1, 'value') and oid_asn1.value != oid_value:
        raise RuntimeError("Failed to decode OID {}: got {} instead".format(oid_asn1.value, oid_value))

    # Decode well-known Object IDs
    if oid_value == '1.2.840.10040.4.1':
        # {iso(1) member-body(2) us(840) x9-57(10040) x9algorithm(4) dsa(1)}
        return 'dsaEncryption'
    if oid_value == '1.2.840.113549.1.1.1':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) rsaEncryption(1)}
        # RSAES-PKCS1-v1_5 encryption scheme
        return 'rsaEncryption'

    if oid_value == '1.2.840.113549.1.5.12':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-5(5) pBKDF2(12)}
        return 'pbkdf2'
    if oid_value == '1.2.840.113549.1.5.13':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-5(5) pbes2(13)}
        return 'pbes2'

    if oid_value == '1.2.840.113549.1.7.1':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7) data(1)}
        return 'pkcs7-data'
    if oid_value == '1.2.840.113549.1.7.2':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7) signedData(2)}
        return 'pkcs7-signedData'
    if oid_value == '1.2.840.113549.1.7.3':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7) envelopedData(3)}
        return 'pkcs7-envelopedData'
    if oid_value == '1.2.840.113549.1.7.4':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7) signedAndEnvelopedData(4)}
        return 'pkcs7-signedAndEnvelopedData'
    if oid_value == '1.2.840.113549.1.7.5':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7) digestedData(5)}
        return 'pkcs7-digestedData'
    if oid_value == '1.2.840.113549.1.7.6':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7) encryptedData(6)}
        return 'pkcs7-encryptedData'

    if oid_value == '1.2.840.113549.1.9.20':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) friendlyName(20)}
        return 'friendlyName'
    if oid_value == '1.2.840.113549.1.9.21':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) localKeyID(21)}
        return 'localKeyID'
    if oid_value == '1.2.840.113549.1.9.22.1':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) certTypes(22) x509Certificate(1)}
        return 'x509Certificate'

    if oid_value == '1.2.840.113549.1.12.1.1':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-12(12) pkcs-12PbeIds(1)
        #  pbeWithSHAAnd128BitRC4(1)}
        return 'pbeWithSHA1And128BitRC4'
    if oid_value == '1.2.840.113549.1.12.1.2':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-12(12) pkcs-12PbeIds(1)
        #  pbeWithSHAAnd40BitRC4(2)}
        return 'pbeWithSHA1And40BitRC4'
    if oid_value == '1.2.840.113549.1.12.1.3':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-12(12) pkcs-12PbeIds(1)
        #  pbeWithSHAAnd3-KeyTripleDES-CBC(3)}
        return 'pbeWithSHA1And3-KeyTripleDES-CBC'
    if oid_value == '1.2.840.113549.1.12.1.4':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-12(12) pkcs-12PbeIds(1)
        #  pbeWithSHAAnd2-KeyTripleDES-CBC(4)}
        return 'pbeWithSHA1And2-KeyTripleDES-CBC'
    if oid_value == '1.2.840.113549.1.12.1.5':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-12(12) pkcs-12PbeIds(1)
        #  pbeWithSHAAnd128BitRC2-CBC(5)}
        # In Java: PBE/SHA1/RC2/CBC/PKCS12PBE-5-128 (when using 5 iterations)
        return 'pbeWithSHA1And128BitRC2-CBC'
    if oid_value == '1.2.840.113549.1.12.1.6':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-12(12) pkcs-12PbeIds(1)
        #  pbeWithSHAAnd40BitRC2-CBC(6)}
        return 'pbeWithSHA1And40BitRC2-CBC'

    if oid_value == '1.2.840.113549.1.12.10.1.2':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-12(12) pkcs-12Version1(10)
        #  pkcs-12BagIds(1) keyBag(1)}
        return 'keyBag'
    if oid_value == '1.2.840.113549.1.12.10.1.2':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-12(12) pkcs-12Version1(10)
        #  pkcs-12BagIds(1) pkcs-8ShroudedKeyBag(2)}
        return 'pkcs8ShroudedKeyBag'
    if oid_value == '1.2.840.113549.1.12.10.1.3':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-12(12) pkcs-12Version1(10)
        #  pkcs-12BagIds(1) certBag(3)}
        return 'certBag'
    if oid_value == '1.2.840.113549.1.12.10.1.4':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-12(12) pkcs-12Version1(10)
        #  pkcs-12BagIds(1) crlBag(4)}
        return 'crlBag'
    if oid_value == '1.2.840.113549.1.12.10.1.5':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-12(12) pkcs-12Version1(10)
        #  pkcs-12BagIds(1) secretBag(5)}
        return 'secretBag'
    if oid_value == '1.2.840.113549.1.12.10.1.6':
        # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-12(12) pkcs-12Version1(10)
        #  pkcs-12BagIds(1) safeContentsBag(6)}
        return 'safeContentsBag'

    if oid_value == '1.2.840.113549.2.9':
        # {iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) hmacWithSHA256(9)}
        return 'hmacWithSHA256'

    if oid_value == '1.3.14.3.2.26':
        # {iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) hashAlgorithmIdentifier(26)}
        return 'sha1'

    if oid_value == '2.16.840.1.101.3.4.1':
        # {joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) aes(1)}
        return 'aes'
    if oid_value == '2.16.840.1.101.3.4.1.42':
        # {joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithms(4) aes(1)
        #  aes256-CBC-PAD(42)}
        return 'aes256-CBC-PAD'

    if oid_value == '2.16.840.1.101.3.4.2.1':
        # {joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithms(4) hashalgs(2)
        #  sha256(1)}
        return 'sha256'

    return oid_value


# PKCS#12 Password-Based Encryption algorithms
PKCS12_PBE_ALGS = frozenset((
    'pbeWithSHA1And128BitRC4',
    'pbeWithSHA1And40BitRC4',
    'pbeWithSHA1And3-KeyTripleDES-CBC',
    'pbeWithSHA1And2-KeyTripleDES-CBC',
    'pbeWithSHA1And128BitRC2-CBC',
    'pbeWithSHA1And40BitRC2-CBC',
))


class PKCS12PbeAlg(object):
    """Represent a PKCS#12 Password-Based Encryption algorithm with parameters"""
    def __init__(self, oid_name, salt, iterations):
        assert oid_name in PKCS12_PBE_ALGS
        self.oid_name = oid_name
        self.salt = salt
        self.iterations = iterations

    def __str__(self):
        return "{}(salt={}, iterations={})".format(
            self.oid_name.strip(':'), util_bin.xx(self.salt), self.iterations)

    @classmethod
    def from_der_parameters(cls, oid_name, params_der):
        """Parse parameters in DER form"""
        assert oid_name in PKCS12_PBE_ALGS
        # pkcs-12PbeParams ::= SEQUENCE {
        #     salt        OCTET STRING,
        #     iterations  INTEGER
        # }
        salt_der, iterations = decode_sequence(params_der, 2)
        salt = decode_octet_string(salt_der)
        return cls(oid_name, salt, iterations)


class PKCS12Pbes2Alg(object):
    """Represent a PKCS#12 Password-Based Encryption using PBKDF2

    cf. https://datatracker.ietf.org/doc/html/rfc8018#appendix-A.4

        id-PBES2 OBJECT IDENTIFIER ::= {pkcs-5 13}
        PBES2-params ::= SEQUENCE {
          keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
          encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }
    """
    def __init__(self, salt, iterations, dklen, prf_alg, enc_alg, enc_iv):
        self.salt = salt
        self.iterations = iterations
        self.dklen = dklen
        self.prf_alg = prf_alg
        self.enc_alg = enc_alg
        self.enc_iv = enc_iv

    def __str__(self):
        return "PBKDF2(salt={}, iterations={}, dklen={}, enc={}, enciv={})".format(
            util_bin.xx(self.salt), self.iterations, self.dklen, self.enc_alg, util_bin.xx(self.enc_iv))

    @classmethod
    def from_der_parameters(cls, params_der):
        """Parse parameters in DER form"""
        kdf_seq_raw, enc_seq_raw = decode_sequence(params_der, 2)
        kdf_seq = decode_sequence(kdf_seq_raw, 2)
        kdf_alg_id = decode_oid(kdf_seq[0])
        if kdf_alg_id != 'pbkdf2':
            raise ValueError("Unexpected Pbes2 KDF OID {}".format(kdf_alg_id))
        kdf_params = decode_sequence(kdf_seq[1], 4)
        salt = decode_octet_string(kdf_params[0])
        iterations = kdf_params[1]
        dklen = kdf_params[2]
        prf_alg_seq = decode_sequence(kdf_params[3], 2)
        prf_alg_id = decode_oid(prf_alg_seq[0])
        prf_alg_params = prf_alg_seq[1]
        if prf_alg_id == 'hmacWithSHA256' and prf_alg_params == b'\x05\x00':
            prf_alg = 'sha256'
        else:
            raise NotImplementedError("Unimplemented Pbes2 PRF algorithm {}".format(prf_alg_id))
        enc_seq = decode_sequence(enc_seq_raw, 2)
        enc_alg_id = decode_oid(enc_seq[0])
        enc_alg_params = enc_seq[1]
        if enc_alg_id == 'aes256-CBC-PAD':
            enc_iv = decode_octet_string(enc_alg_params)
            assert len(enc_iv) == 16
            return cls(salt, iterations, dklen, prf_alg, enc_alg_id, enc_iv)
        raise NotImplementedError("Unimplemented Pbes2 encryption algorithm {}".format(enc_alg_id))

    @classmethod
    def self_test(cls):
        """Check that the implementation works"""
        params_der = binascii.unhexlify(
            '3059303806092a864886f70d01050c302b0414cef0098d02991b428da712c3a8'
            '520537ab207cfc02022710020120300c06082a864886f70d02090500301d0609'
            '60864801650304012a0410ef539601ee5e7ef13ed1b36b71b7e4e1')
        obj = cls.from_der_parameters(params_der)
        assert obj.salt == binascii.unhexlify('cef0098d02991b428da712c3a8520537ab207cfc')
        assert obj.iterations == 10000
        assert obj.dklen == 32
        assert obj.prf_alg == 'sha256'
        assert obj.enc_alg == 'aes256-CBC-PAD'
        assert obj.enc_iv == binascii.unhexlify('ef539601ee5e7ef13ed1b36b71b7e4e1')


PKCS12Pbes2Alg.self_test()


def decode_x509_algid(der_algorithm_identifier):
    """Decode an X.509 AlgorithmIdentifier object

    Defined in https://tools.ietf.org/html/rfc2459 as:
        AlgorithmIdentifier  ::=  SEQUENCE  {
            algorithm               OBJECT IDENTIFIER,
            parameters              ANY DEFINED BY algorithm OPTIONAL
        }
    """
    algo_id_asn1 = decode_sequence(der_algorithm_identifier, counts=(1, 2))
    alg_id = decode_oid(algo_id_asn1[0])
    alg_params = algo_id_asn1[1] if len(algo_id_asn1) >= 2 else None
    if alg_params == b'\x05\x00':  # NULL
        alg_params = None
    if alg_id == 'sha1' and not alg_params:
        return 'SHA1'
    if alg_id == 'sha256' and not alg_params:
        return 'SHA256'
    if alg_id == 'dsaEncryption' and alg_params:
        # For DSA, algorithm parameters contain DSA numbers
        return 'DSA'
    if alg_id == 'rsaEncryption' and not alg_params:
        return 'RSA'
    if alg_id == 'aes' and not alg_params:
        return 'AES'

    if alg_id in PKCS12_PBE_ALGS:
        return PKCS12PbeAlg.from_der_parameters(alg_id, alg_params)

    if alg_id == 'pbes2':
        return PKCS12Pbes2Alg.from_der_parameters(alg_params)

    return 'Unknown<OID={}, params={}>'.format(alg_id, repr(alg_params))


def show_pkcs8_private_key_info(privkey_der, list_only=False, show_pem=False, indent=''):
    """Decode a PKCS#8 PrivateKeyInfo structure in ASN.1 DER format and show it"""
    # PKCS#8 (https://tools.ietf.org/html/rfc5208)
    # PrivateKeyInfo ::= SEQUENCE {
    #     version                   Version,
    #     privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
    #     privateKey                PrivateKey,
    #     attributes           [0]  IMPLICIT Attributes OPTIONAL
    # }
    # Version ::= INTEGER
    # PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
    # PrivateKey ::= OCTET STRING
    # Attributes ::= SET OF Attribute
    version, privatekey_algid_der, privatekey_der = decode_sequence(privkey_der, 3)
    if version != 0:
        raise ValueError("Unknown PrivateKeyInfo version {}".format(version))
    privatekey_algid = decode_x509_algid(privatekey_algid_der)
    key_value = decode_octet_string(privatekey_der)

    if privatekey_algid == 'DSA':
        print("{}* DSA private key".format(indent))
        util_bin.run_openssl_show_dsa(privkey_der, list_only=list_only, show_pem=show_pem, indent=indent)
    elif privatekey_algid == 'RSA':
        print("{}* RSA private key".format(indent))
        util_bin.run_openssl_show_rsa(privkey_der, list_only=list_only, show_pem=show_pem, indent=indent)
    elif privatekey_algid == 'AES':
        if list_only:
            print("{}* AES key: {} bytes ({} bits)".format(indent, len(key_value), 8 * len(key_value)))
        else:
            print("{}* AES key ({} bytes): {}".format(indent, len(key_value), util_bin.xx(key_value)))
            print("{}    * repr: {}".format(indent, repr(key_value)))
        return
    else:
        util_bin.run_openssl_asn1parse(privatekey_algid_der)
        raise ValueError("Unknown encryption algorithm {}".format(privatekey_algid))
