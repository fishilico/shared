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
"""Parse the Authenticode signature of a PE file

Authenticode is based on the Public-Key Cryptography Standards (PKCS) #7
standard and uses X.509 v3 certificates to bind an Authenticode-signed file to
the identity of a software publisher.

Documentation:
* https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx
  Windows Authenticode Portable Executable Signature Format
* https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography
  Object IDs associated with Microsoft cryptography

@author: Nicolas Iooss
@license: MIT
"""
import binascii
import datetime
import logging
import re
import struct
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

import Crypto.Util.asn1
import cryptography.hazmat.backends
import cryptography.x509


# pylint: disable=invalid-name
logger = logging.getLogger(__name__)


# Well-known Object IDs
KNOWN_OID = {
    # {itu-t(0) data(9) pss(2342) ucl(19200300) pilot(100) pilotAttributeType(1) domainComponent(25)}
    '0.9.2342.19200300.100.1.25': 'domainComponent',

    # {iso(1) member-body(2) us(840) x9-57(10040) x9algorithm(4) dsa(1)}
    '1.2.840.10040.4.1': 'dsa',

    # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1)}
    '1.2.840.113549.1.1.1': 'rsaEncryption',  # RSAES PKCS#1 v1.5
    '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
    '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',

    # {iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2)}
    '1.2.840.113549.2.5': 'md5',

    # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7)}
    '1.2.840.113549.1.7.2': 'pkcs7-signedData',

    # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)}
    '1.2.840.113549.1.9.3': 'id-contentType',
    '1.2.840.113549.1.9.4': 'id-messageDigest',
    '1.2.840.113549.1.9.5': 'id-signingTime',
    '1.2.840.113549.1.9.6': 'id-countersignature',

    # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16)
    #  ct(1) tstInfo(4)}
    '1.2.840.113549.1.9.16.1.4': 'id-ct-TSTInfo',

    # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16)
    #  id-aa(2) signing-certificate(12)}
    '1.2.840.113549.1.9.16.2.12': 'id-aa-signingCertificate',
    # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16)
    #  id-aa(2) id-aa-signingCertificateV2(47)}
    '1.2.840.113549.1.9.16.2.47': 'id-aa-signingCertificateV2',

    # {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
    #  pkcs-9-at(25) sequenceNumber(4)}
    '1.2.840.113549.1.9.25.4': 'sequenceNumber',

    # {iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) microsoft(311) authenticode(2)}
    '1.3.6.1.4.1.311.2.1.4': 'SPC_INDIRECT_DATA_OBJID',
    '1.3.6.1.4.1.311.2.1.11': 'SPC_STATEMENT_TYPE_OBJID',
    '1.3.6.1.4.1.311.2.1.10': 'SPC_SP_AGENCY_INFO_OBJID',
    '1.3.6.1.4.1.311.2.1.12': 'SPC_SP_OPUS_INFO_OBJID',
    '1.3.6.1.4.1.311.2.1.14': 'SPC_CERT_EXTENSIONS_OBJID',
    '1.3.6.1.4.1.311.2.1.15': 'SPC_PE_IMAGE_DATA_OBJID',
    '1.3.6.1.4.1.311.2.1.18': 'SPC_RAW_FILE_DATA_OBJID',
    '1.3.6.1.4.1.311.2.1.19': 'SPC_STRUCTURED_STORAGE_DATA_OBJID',
    '1.3.6.1.4.1.311.2.1.20': 'SPC_JAVA_CLASS_DATA_OBJID',
    '1.3.6.1.4.1.311.2.1.21': 'SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID',
    '1.3.6.1.4.1.311.2.1.22': 'SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID',
    '1.3.6.1.4.1.311.2.1.25': 'SPC_CAB_DATA_OBJID',
    '1.3.6.1.4.1.311.2.1.25  ': 'SPC_GLUE_RDN_OBJID',
    '1.3.6.1.4.1.311.2.1.26': 'SPC_MINIMAL_CRITERIA_OBJID',
    '1.3.6.1.4.1.311.2.1.27': 'SPC_FINANCIAL_CRITERIA_OBJID',
    '1.3.6.1.4.1.311.2.1.28': 'SPC_LINK_OBJID',
    '1.3.6.1.4.1.311.2.1.29': 'SPC_HASH_INFO_OBJID',
    '1.3.6.1.4.1.311.2.1.30': 'SPC_SIPINFO_OBJID',

    # CTL for Software Publishers Trusted CA (1.3.6.1.4.1.311.2.2)
    '1.3.6.1.4.1.311.2.2.1': 'szOID_TRUSTED_CODESIGNING_CA_LIST',
    '1.3.6.1.4.1.311.2.2.2': 'szOID_TRUSTED_CLIENT_AUTH_CA_LIST',
    '1.3.6.1.4.1.311.2.2.3': 'szOID_TRUSTED_SERVER_AUTH_CA_LIST',

    # Page hash versions
    '1.3.6.1.4.1.311.2.3.1': 'SPC_PE_IMAGE_PAGE_HASHES_V1_OBJID',
    '1.3.6.1.4.1.311.2.3.2': 'SPC_PE_IMAGE_PAGE_HASHES_V2_OBJID',

    # Attributes that are octet-encoded PKCS#7
    '1.3.6.1.4.1.311.2.4.1': 'szOID_NESTED_SIGNATURE',

    '1.3.6.1.4.1.311.2.6.1': 'SPC_RELAXED_PE_MARKER_CHECK_OBJID',
    '1.3.6.1.4.1.311.2.6.2': 'SPC_ENCRYPTED_DIGEST_RETRY_COUNT_OBJID',

    # Time Stamping (1.3.6.1.4.1.311.3)
    '1.3.6.1.4.1.311.3.2.1': 'SPC_TIME_STAMP_REQUEST_OBJID',
    '1.3.6.1.4.1.311.3.3.1': 'szOID_RFC3161_counterSign',
    '1.3.6.1.4.1.311.10.3.13': 'szOID_KP_LIFETIME_SIGNING',
    '1.3.6.1.4.1.311.10.3.28': 'szOID_PLATFORM_MANIFEST_BINARY_ID',

    '1.3.6.1.4.1.311.10.41.1': 'SPC_WINDOWS_HELLO_COMPATIBILITY_OBJID',

    # Unknown? Used in TSAPolicyId in timestamp counter signing
    '1.3.6.1.4.1.601.10.3.1': 'unknownTimeStampingAuthorityPolicy',

    # {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) kp(3)}
    # Certificate Extended Key Usages
    '1.3.6.1.5.5.7.3.3': 'szOID_PKIX_KP_CODE_SIGNING',
    '1.3.6.1.5.5.7.3.8': 'szOID_PKIX_KP_TIMESTAMP_SIGNING',

    # {iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) hashAlgorithmIdentifier(26)}
    '1.3.14.3.2.26': 'sha1',
    '1.3.14.3.2.29': 'sha1WithRSAEncryption',  # Obsolete ID for 1.2.840.113549.1.1.5

    # {joint-iso-itu-t(2) ds(5) attributeType(4)}
    '2.5.4.3': 'commonName',
    '2.5.4.6': 'countryName',
    '2.5.4.7': 'localityName',
    '2.5.4.8': 'stateOrProvinceName',
    '2.5.4.10': 'organizationName',
    '2.5.4.11': 'organizationalUnitName',

    # {joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4)
    #  hashAlgs(2) sha256(1)}
    '2.16.840.1.101.3.4.2.1': 'sha256',

    # {joint-iso-itu-t(2) country(16) us(840) organization(1) symantec(113733)
    #  pki(1) policies(7) vtn-cp(23) class3(3)}
    '2.16.840.1.113733.1.7.23.3': 'symantec-policies-class3',
}

NAME_TYPE_ABBREVIATION = {
    'commonName': 'CN',
    'countryName': 'C',
    'domainComponent': 'DC',
    'localityName': 'L',
    'organizationName': 'O',
    'organizationalUnitName': 'OU',
    'stateOrProvinceName': 'ST',
}


def split_der_data(der_data: bytes) -> Tuple[bytes, bytes]:
    """Split DER-encoded data with something that goes after"""
    size_size = der_data[1]
    if size_size < 0x80:
        # [1 byte type, 1 byte size, data]
        split_index = 2 + size_size
    else:
        # [1 byte type, 1 byte size of size, size, data]
        size = 0
        size_size &= 0x7f
        for size_byte in der_data[2:2 + size_size]:
            size = (size << 8) | size_byte
        split_index = 2 + size_size + size

    return der_data[:split_index], der_data[split_index:]


def decode_object(der_obj: bytes) -> bytes:
    """Decode an ASN.1 object in DER format"""
    obj_asn1 = Crypto.Util.asn1.DerObject()
    try:
        obj_asn1.decode(der_obj)
    except ValueError as exc:
        logger.error("Unable to decode an ASN.1 object: %s", exc)
        raise
    return obj_asn1.payload


def decode_cont_object(der_obj: bytes, expected_cont: int) -> bytes:
    """Decode an ASN.1 cont object in DER format, used for example in optional fields"""
    obj_asn1 = Crypto.Util.asn1.DerObject()
    try:
        obj_asn1.decode(der_obj)
    except ValueError as exc:
        logger.error("Unable to decode an ASN.1 object: %s", exc)
        raise
    if der_obj[0] != 0xa0 + expected_cont:
        raise ValueError("Unexpected cont tag: {:#x} != 0xa0 + {:#x}".format(der_obj[0], expected_cont))
    return obj_asn1.payload


def decode_sequence(der_seq: bytes,
                    count: Optional[int] = None,
                    counts: Optional[Tuple[int, ...]] = None) -> List[Union[bytes, int]]:
    """Decode an ASN.1 sequence in DER format"""
    seq_asn1 = Crypto.Util.asn1.DerSequence()
    try:
        seq_asn1.decode(der_seq)
    except ValueError as exc:
        logger.error("Unable to decode an ASN.1 sequence: %s", exc)
        raise
    if count is not None and len(seq_asn1) != count:
        raise ValueError("Unexpected number of items in ASN.1 sequence: {} != {}".format(len(seq_asn1), count))
    if counts is not None and len(seq_asn1) not in counts:
        raise ValueError("Unexpected number of items in ASN.1 sequence: {} not in {}".format(len(seq_asn1), counts))
    return seq_asn1[:]  # type: ignore


def decode_sequence_bytes(der_seq: bytes,
                          count: Optional[int] = None,
                          counts: Optional[Tuple[int, ...]] = None) -> List[bytes]:
    """decode_sequence() but always return bytes"""
    result = decode_sequence(der_seq, count=count, counts=counts)
    assert all(isinstance(x, bytes) for x in result)
    return result  # type: ignore


def decode_set(der_set: bytes) -> List[Union[bytes, int]]:
    """Decode an ASN.1 set in DER format"""
    try:
        set_asn1 = Crypto.Util.asn1.DerSetOf()
    except AttributeError:
        # PyCrypto < 2.7 did not implement DerSetOf
        raise NotImplementedError("Crypto.Util.asn1.DerSetOf is not available")
    try:
        set_asn1.decode(der_set)
    except ValueError as exc:
        logger.error("Unable to decode an ASN.1 set: %s", exc)
        raise
    return set_asn1[:]  # type: ignore


def decode_set_bytes(der_seq: bytes) -> List[bytes]:
    """decode_set() but always return bytes"""
    result = decode_set(der_seq)
    assert all(isinstance(x, bytes) for x in result)
    return result  # type: ignore


def decode_octet_string(der_octet_string: bytes) -> bytes:
    """Decode an ASN.1 Octet String in DER format"""
    octet_string_asn1: Union[Crypto.Util.asn1.DerOctetString, Crypto.Util.asn1.DerObject] = \
        Crypto.Util.asn1.DerOctetString()
    try:
        octet_string_asn1.decode(der_octet_string)
    except ValueError as exc:
        logger.error("Unable to decode an ASN.1 octet string: %s", exc)
        raise
    except TypeError:
        # python-crypto 2.6.1-4ubuntu0.3 is buggy on Ubuntu 14.04
        octet_string_asn1 = Crypto.Util.asn1.DerObject()
        octet_string_asn1.decode(der_octet_string)
    return octet_string_asn1.payload


def decode_bmp_string(der_utf8_string: bytes) -> str:
    """Decode an ASN.1 BMP (UTF-16 Big Endian) String in DER format"""
    if der_utf8_string[0] != 0x1e:
        raise ValueError("Unexpected tag for ASN.1 BMP String: {:#x}".format(
            der_utf8_string[0]))
    return decode_object(der_utf8_string).decode('utf-16be')


def decode_utf8_string(der_utf8_string: bytes) -> str:
    """Decode an ASN.1 UTF-8 String in DER format"""
    if der_utf8_string[0] != 0x0c:
        raise ValueError("Unexpected tag for ASN.1 UTF-8 String: {:#x}".format(
            der_utf8_string[0]))
    return decode_object(der_utf8_string).decode('utf-8')


def decode_ia5_string(der_ia5string: bytes) -> str:
    """Decode an ASN.1 IA5String in DER format"""
    if der_ia5string[0] != 0x16:
        raise ValueError("Unexpected tag for ASN.1 IA5String: {:#x}".format(
            der_ia5string[0]))
    return decode_object(der_ia5string).decode('ascii')


def decode_printable_string(der_printable_string: bytes) -> str:
    """Decode an ASN.1 Printable String in DER format"""
    if der_printable_string[0] != 0x13:
        raise ValueError("Unexpected tag for ASN.1 Printable String: {:#x}".format(
            der_printable_string[0]))
    return decode_object(der_printable_string).decode('ascii')


def decode_teletex_string(der_t61string: bytes) -> str:
    """Decode an ASN.1 T61String (Teletex String) in DER format"""
    if der_t61string[0] != 0x14:
        raise ValueError("Unexpected tag for ASN.1 T61String: {:#x}".format(
            der_t61string[0]))
    return decode_object(der_t61string).decode('ascii')


def decode_oid(der_objectid: bytes) -> str:
    """Decode an ASN.1 Object ID in DER format"""
    oid_asn1: Union[Crypto.Util.asn1.DerObjectId, Crypto.Util.asn1.DerObject] = \
        Crypto.Util.asn1.DerObjectId()
    try:
        oid_asn1.decode(der_objectid)
    except ValueError as exc:
        logger.error("Unable to decode an ASN.1 object ID: %s (for %s)", exc,
                     binascii.hexlify(der_objectid).decode('ascii'))
        raise
    except TypeError:
        # python-crypto 2.6.1-4ubuntu0.3 is buggy on Ubuntu 14.04:
        #   File "/usr/lib/python2.7/dist-packages/Crypto/Util/asn1.py", line 274, in decode
        #     p = DerObject.decode(derEle, noLeftOvers)
        # TypeError: unbound method decode() must be called with DerObject instance as first argument
        #   (got str instance instead)
        # ... so fallback to a raw DerObject()
        oid_asn1 = Crypto.Util.asn1.DerObject()
        oid_asn1.decode(der_objectid)

    # PyCrypto < 2.7 did not decode the Object Identifier. Let's implement OID decoding
    components = []
    current_val = 0
    for idx, byteval in enumerate(oid_asn1.payload):
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
    if isinstance(oid_asn1, Crypto.Util.asn1.DerObjectId) and hasattr(oid_asn1, 'value'):
        if oid_asn1.value != oid_value:
            raise RuntimeError("Failed to decode OID {}: got {} instead".format(oid_asn1.value, oid_value))
    oid_name = KNOWN_OID.get(oid_value)
    if oid_name:
        return oid_name
    logger.warning("Unknown OID %r", oid_value)
    return oid_value


def decode_x509_algid(der_algorithm_identifier: bytes) -> str:
    """Decode an X.509 AlgorithmIdentifier object

    Defined in https://tools.ietf.org/html/rfc2459 as:
        AlgorithmIdentifier ::= SEQUENCE {
            algorithm OBJECT IDENTIFIER,
            parameters ANY DEFINED BY algorithm OPTIONAL
        }
    """
    algo_id_asn1 = decode_sequence_bytes(der_algorithm_identifier, counts=(1, 2))
    alg_id = decode_oid(algo_id_asn1[0])
    alg_params = algo_id_asn1[1] if len(algo_id_asn1) >= 2 else None
    if alg_params == b'\x05\x00':  # NULL
        alg_params = None

    if alg_id == 'md5' and not alg_params:
        return 'MD5'
    if alg_id == 'rsaEncryption' and not alg_params:
        return 'RSA'
    if alg_id == 'sha1' and not alg_params:
        return 'SHA1'
    if alg_id == 'sha1WithRSAEncryption' and not alg_params:
        return 'RSA-SHA251'
    if alg_id == 'sha256' and not alg_params:
        return 'SHA256'
    if alg_id == 'sha256WithRSAEncryption' and not alg_params:
        return 'RSA-SHA256'

    logger.warning("Unknown algorithm identifier %r (params %r)", alg_id, alg_params)
    return 'Unknown<OID={}, params={}>'.format(alg_id, repr(alg_params))


def decode_x509_name_type_and_value(der_object: bytes) -> str:
    """Decode an X.509 AttributeTypeAndValue object used in Name object"""
    type_der, value_der = decode_sequence_bytes(der_object, count=2)
    type_oid = decode_oid(type_der)
    type_abbrev = NAME_TYPE_ABBREVIATION.get(type_oid)
    if not type_abbrev:
        raise NotImplementedError("Unknown Name type OID {}".format(repr(type_oid)))
    if type_abbrev == 'DC':
        value = decode_ia5_string(value_der)
    elif value_der[0] == 0x14:  # The string may be a Teletex String
        value = decode_teletex_string(value_der)
    else:
        value = decode_printable_string(value_der)
    return "{}={}".format(type_abbrev, value)


def decode_x509_name(der_name: bytes) -> str:
    """Decode an X.509 Name object

    Defined in https://tools.ietf.org/html/rfc2459 as:

        Name ::= CHOICE { rdnSequence  RDNSequence }
        RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
        RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
        AttributeTypeAndValue ::= SEQUENCE {
            type AttributeType,
            value AttributeValue
        }
        AttributeType ::= OBJECT IDENTIFIER
        AttributeValue ::= ANY -- DEFINED BY AttributeType
    """
    return ','.join(
        ','.join(decode_x509_name_type_and_value(x) for x in decode_set_bytes(seq))
        for seq in decode_sequence_bytes(der_name))


def describe_der_certificate(certificate: bytes) -> Dict[str, Union[int, str]]:
    """Craft a description of a certificate in DER format"""
    backend = cryptography.hazmat.backends.default_backend()
    cert = cryptography.x509.load_der_x509_certificate(certificate, backend)
    try:
        cert_subject: Optional[cryptography.x509.Name] = cert.subject
    except ValueError as exc:
        # This happens for example when using C=Unknown
        # ("Country name must be a 2 character country code")
        logger.error("PyCryptography failed to load the certificate subject: %s", exc)
        cert_subject = None

    try:
        cert_issuer: Optional[cryptography.x509.Name] = cert.issuer
    except ValueError as exc:
        logger.error("PyCryptography failed to load the certificate issuer: %s", exc)
        cert_issuer = None

    desc: Dict[str, Union[int, str]] = {}
    if cert_subject is not None:
        name_bytes = cert_subject.public_bytes(backend)
        desc['subject'] = decode_x509_name(name_bytes)
    else:
        desc['subject'] = "(invalid subject)"
    if cert_issuer is not None:
        if cert_issuer == cert_subject:
            desc['issuer'] = "self-signed"
        else:
            name_bytes = cert_issuer.public_bytes(backend)
            desc['issuer'] = decode_x509_name(name_bytes)
    desc['serial_number'] = cert.serial_number
    signature_alg_oid: str = cert.signature_algorithm_oid.dotted_string  # type: ignore
    signature_alg_name = KNOWN_OID.get(signature_alg_oid)
    if not signature_alg_name:
        logger.warning("Unknown X.509 certificate signature alorigthm OID %r for %r",
                       signature_alg_oid, cert.signature_algorithm_oid)
        signature_alg_name = signature_alg_oid
    desc['signature_alg'] = signature_alg_name
    desc['not_valid_before'] = cert.not_valid_before.strftime('%Y-%m-%d')
    desc['not_valid_after'] = cert.not_valid_after.strftime('%Y-%m-%d')
    return desc


def decode_spc_string(der_spc_string: bytes) -> str:
    """Decode an Authenticode SpcString in DER format

    ASN.1 structure:
        SpcString ::= CHOICE {
            unicode [0] IMPLICIT BMPSTRING,
            ascii [1] IMPLICIT IA5STRING
        }
    """
    if der_spc_string[0] == 0x80:
        # Unicode (there is no sub-tag to define a BMP string)
        return decode_object(der_spc_string).decode('utf-16be')
    if der_spc_string[0] == 0x81:
        # ASCII
        return decode_object(der_spc_string).decode('ascii')
    raise ValueError("Unexpected choice for SpcString: {}".format(repr(der_spc_string)))


class AuthenticodeSpcLink:
    """Authenticode SpcLink

    ASN.1 structure:
        SpcLink ::= CHOICE {
            url [0] IMPLICIT IA5STRING,
            moniker [1] IMPLICIT SpcSerializedObject,
            file [2] EXPLICIT SpcString
        }
    """
    def __init__(self, der_content: bytes):
        if der_content[0] == 0x80:
            self.kind = 'url'
            self.value: Union[str, bytes] = decode_object(der_content).decode('ascii')
        elif der_content[0] == 0x81:
            self.kind = 'moniker'
            # Do not decode a SpcSerializedObject for now
            self.value = decode_object(der_content)
        elif der_content[0] == 0x82:
            self.kind = 'file'
            self.value = decode_spc_string(decode_object(der_content))
        else:
            raise ValueError("Unexpected choice for SpcLink: {}".format(repr(der_content)))

    def to_dict_description(self) -> Mapping[str, Union[str, bytes]]:
        """Convert to a dictionary describing the object"""
        return {self.kind: self.value}


class AuthenticodeSpcPeImageData:
    """Authenticode SpcPeImageData

    ASN.1 structure:
        SpcPeImageData ::= SEQUENCE {
            flags SpcPeImageFlags DEFAULT { includeResources },
            file SpcLink
        }
        SpcPeImageFlags ::= BIT STRING {
            includeResources (0),
            includeDebugInfo (1),
            includeImportAddressTable (2)
        }
    """
    def __init__(self, der_content: bytes):
        flags_der, file_der = decode_sequence_bytes(der_content, count=2)
        if flags_der[0] != 3:
            raise ValueError("Unexpected tag for SpcPeImageFlags in SpcPeImageData: {}".format(
                repr(flags_der)))
        flags_bit_string = decode_object(flags_der)
        if flags_bit_string == b'\0':
            self.flags = 'includeResources'
        elif flags_bit_string == b'\x01':
            self.flags = 'includeDebugInfo'
        elif flags_bit_string == b'\x02':
            self.flags = 'includeImportAddressTable'
        else:
            raise ValueError("Unexpected flags in SpcPeImageData: {}".format(repr(flags_bit_string)))

        # Do not decode this structure, as it usually contains a structure
        # related to page hashes.
        self.file_der = file_der

    def to_dict_description(self) -> Mapping[str, str]:
        """Convert to a dictionary describing the object"""
        return {
            'flags': self.flags,
            'file': "({} bytes possibly with page hashes)".format(len(self.file_der)),
        }


class AuthenticodeSpcIndirectDataContent:
    """Authenticode SpcIndirectDataContent

    ASN.1 structure:
        SpcIndirectDataContent ::= SEQUENCE {
            data SpcAttributeTypeAndOptionalValue,
            messageDigest DigestInfo
        }
        SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
            type ObjectID,
            value [0] EXPLICIT ANY OPTIONAL
        }
        DigestInfo ::= SEQUENCE {
            digestAlgorithm AlgorithmIdentifier,
            digest OCTETSTRING
        }
        AlgorithmIdentifier ::= SEQUENCE {
            algorithm ObjectID,
            parameters [0] EXPLICIT ANY OPTIONAL
        }
    """
    def __init__(self, der_content: bytes):
        data_der, message_digest_der = decode_sequence_bytes(der_content, count=2)
        data_type_der, data_value_der = decode_sequence_bytes(data_der, count=2)
        self.data_type = decode_oid(data_type_der)
        if self.data_type != 'SPC_PE_IMAGE_DATA_OBJID':
            raise ValueError("Unexpected data type in SpcIndirectDataContent: {}".format(
                repr(self.data_type)))
        self.data_value = AuthenticodeSpcPeImageData(data_value_der)
        digest_alg_der, digest_der = decode_sequence_bytes(message_digest_der, count=2)
        self.digest_alg = decode_x509_algid(digest_alg_der)
        self.digest = decode_octet_string(digest_der)

    def to_dict_description(self) -> Mapping[str, Union[str, Mapping[str, str]]]:
        """Convert to a dictionary describing the object"""
        return {
            'data': self.data_value.to_dict_description(),
            'digest_alg': self.digest_alg,
            'digest': binascii.hexlify(self.digest).decode('ascii'),
        }


class Rfc3161TSTInfo:
    """TSTInfo from RFC3161: Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)

    ASN.1 structure:
        TSTInfo ::= SEQUENCE  {
            version INTEGER  { v1(1) },
            policy TSAPolicyId,
            messageImprint MessageImprint,
            serialNumber INTEGER,
            genTime GeneralizedTime,
            accuracy Accuracy OPTIONAL,
            ordering BOOLEAN DEFAULT FALSE,
            nonce INTEGER OPTIONAL,
            tsa [0] GeneralName OPTIONAL,
            extensions [1] IMPLICIT Extensions OPTIONAL
        }
        MessageImprint ::= SEQUENCE {
            hashAlgorithm AlgorithmIdentifier,
            hashedMessage OCTET STRING
        }
        Accuracy ::= SEQUENCE {
            seconds INTEGER OPTIONAL,
            millis [0] INTEGER (1..999) OPTIONAL,
            micros [1] INTEGER (1..999) OPTIONAL
        }
    """
    def __init__(self, der_content: bytes):
        seq = decode_sequence(der_content, counts=(7,))
        assert isinstance(seq[0], int)
        assert isinstance(seq[1], bytes)
        assert isinstance(seq[2], bytes)
        assert isinstance(seq[3], int)
        assert isinstance(seq[4], bytes)
        assert isinstance(seq[5], bytes)
        assert isinstance(seq[6], bytes)

        self.version = seq[0]
        if self.version != 1:
            raise ValueError("Unexpected version in TSTInfo: {}".format(
                repr(self.version)))

        self.tsa_policy_id = decode_oid(seq[1])
        if self.tsa_policy_id not in ('unknownTimeStampingAuthorityPolicy', 'symantec-policies-class3'):
            raise ValueError("Unexpected policy in TSTInfo: {}".format(
                repr(self.tsa_policy_id)))

        msg_hash_alg_der, msg_hash_der = decode_sequence_bytes(seq[2], count=2)
        self.msg_hash_alg = decode_x509_algid(msg_hash_alg_der)
        self.msg_hash = decode_octet_string(msg_hash_der)

        self.serial_number = seq[3]

        gen_time_der = seq[4]
        if gen_time_der[0] != 0x18:
            raise ValueError("Unexpected tag for GeneralizedTime in TSTInfo: {}".format(
                repr(gen_time_der)))
        self.gen_time_str = decode_object(gen_time_der).decode('ascii')
        if not self.gen_time_str.endswith('Z'):
            raise ValueError("Unexpected timezone for GeneralizedTime in TSTInfo: {}".format(
                repr(self.gen_time_str)))
        if '.' in self.gen_time_str:
            # Format "YYYYmmddHHMMSS.fffZ" when "f" is the floating part
            gen_time_seconds, get_time_remaining = self.gen_time_str[:-1].split('.', 2)
            self.gen_time = datetime.datetime.strptime(gen_time_seconds, '%Y%m%d%H%M%S')
            gen_time_micros = get_time_remaining + '0' * (6 - len(get_time_remaining))
            self.gen_time += datetime.timedelta(microseconds=int(gen_time_micros))
        else:
            # Format "YYYYmmddHHMMSSZ"
            self.gen_time = datetime.datetime.strptime(self.gen_time_str[:-1], '%Y%m%d%H%M%S')

        self.accuracy = 0.
        for accuracy_der in decode_sequence(seq[5], counts=(1, 2, 3)):
            if isinstance(accuracy_der, int):
                # seconds
                self.accuracy += accuracy_der
            elif accuracy_der[0] == 0x80:
                # millis
                accuracy_int, = struct.unpack('>H', decode_object(accuracy_der))
                self.accuracy += accuracy_int / 1000.
            elif accuracy_der[0] == 0x81:
                # micros
                accuracy_int, = struct.unpack('>H', decode_object(accuracy_der))
                self.accuracy += accuracy_int / 1000000.
            else:
                raise ValueError("Unexpected tag for Accuracy in TSTInfo: {}".format(
                    repr(accuracy_der)))

        tsa_der = decode_cont_object(seq[6], 0)
        tsa_name_der = decode_cont_object(tsa_der, 4)
        self.tsa_name = decode_x509_name(tsa_name_der)

    def to_dict_description(self) -> Mapping[str, Union[float, int, str]]:
        """Convert to a dictionary describing the object"""
        return {
            'tsa_policy_id': self.tsa_policy_id,
            'msg_hash_alg': self.msg_hash_alg,
            'msg_hash': binascii.hexlify(self.msg_hash).decode('ascii'),
            'serial_number': self.serial_number,
            'gen_time_str': self.gen_time_str,
            'gen_time_iso': str(self.gen_time),
            'accuracy': self.accuracy,
            'tsa_name': self.tsa_name,
        }


class AuthenticodeContentInfo:
    """Authenticode ContentInfo

    ASN.1 structure:
        ContentInfo ::= SEQUENCE {
            contentType ContentType,
            content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
        }
        ContentType ::= OBJECT IDENTIFIER

        content is SpcIndirectDataContent when contentType is SPC_INDIRECT_DATA_OBJID
    """
    def __init__(self, der_content: bytes, is_timestamp_countersign: bool = False):
        content_type_der, content_der = decode_sequence_bytes(der_content, count=2)
        self.content_type = decode_oid(content_type_der)
        if not is_timestamp_countersign:
            if self.content_type != 'SPC_INDIRECT_DATA_OBJID':
                raise ValueError("Unexpected contentType in ContentInfo: {}".format(
                    repr(self.content_type)))
            content_der = decode_cont_object(content_der, 0)
            self.content: Union[AuthenticodeSpcIndirectDataContent, Rfc3161TSTInfo] = \
                AuthenticodeSpcIndirectDataContent(content_der)
        else:
            if self.content_type != 'id-ct-TSTInfo':
                raise ValueError("Unexpected contentType in counter signed timestamp ContentInfo: {}".format(
                    repr(self.content_type)))
            content_der = decode_cont_object(content_der, 0)
            content_der = decode_octet_string(content_der)
            self.content = Rfc3161TSTInfo(content_der)

    def to_dict_description(self) -> Mapping[str, Any]:
        """Convert to a dictionary describing the object"""
        return self.content.to_dict_description()


class AuthenticodeSpcSpOpusInfo:
    """Authenticode SpcSpOpusInfo

    ASN.1 structure:
    SpcSpOpusInfo ::= SEQUENCE {
        programName [0] EXPLICIT SpcString OPTIONAL,
        moreInfo [1] EXPLICIT SpcLink OPTIONAL,
    }
    """
    def __init__(self, der_content: bytes):
        seq = decode_sequence_bytes(der_content, counts=(0, 1, 2))
        self.program_name = None
        self.more_info = None
        if len(seq) == 0:
            return
        if len(seq) == 1:
            if seq[0].startswith(b'\xa0'):
                program_name_der = decode_cont_object(seq[0], 0)
                self.program_name = decode_spc_string(program_name_der)
            elif seq[0].startswith(b'\xa1'):
                more_info_der = decode_cont_object(seq[0], 1)
                self.more_info = AuthenticodeSpcLink(more_info_der)
            else:
                raise ValueError("Unexpected tag value in SpcSpOpusInfo: {}".format(repr(seq[0])))
            return
        assert len(seq) == 2
        program_name_der = decode_cont_object(seq[0], 0)
        self.program_name = decode_spc_string(program_name_der)
        more_info_der = decode_cont_object(seq[1], 1)
        self.more_info = AuthenticodeSpcLink(more_info_der)

    def to_dict_description(self) -> Mapping[str, Any]:
        """Convert to a dictionary describing the object"""
        result: Dict[str, Any] = {}
        if self.program_name:
            result['program_name'] = self.program_name
        if self.more_info:
            result['more_info'] = self.more_info.to_dict_description()
        return result


class AuthenticodeSignerInfo:
    """Authenticode SignerInfo

    ASN.1 structure:
        SignerInfo ::= SEQUENCE {
            version Version,
            issuerAndSerialNumber IssuerAndSerialNumber,
            digestAlgorithm DigestAlgorithmIdentifier,
            authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
            digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
            encryptedDigest EncryptedDigest,
            unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL
        }
        IssuerAndSerialNumber ::= SEQUENCE {
            issuer Name,
            serialNumber CertificateSerialNumber
        }
        EncryptedDigest ::= OCTET STRING
    """
    def __init__(self, der_content: bytes, is_timestamp_countersign: bool = False):
        self._is_timestamp_countersign = is_timestamp_countersign
        seq = decode_sequence(der_content, counts=(5, 6, 7))
        assert isinstance(seq[0], int)
        assert isinstance(seq[1], bytes)
        assert isinstance(seq[2], bytes)

        self.version = seq[0]
        if self.version != 1:
            raise ValueError("Unexpected version in SignerInfo: {}".format(
                repr(self.version)))

        issuer_der, serial_number = decode_sequence(seq[1], count=2)
        assert isinstance(issuer_der, bytes)
        assert isinstance(serial_number, int)
        self.serial_number = serial_number
        self.issuer = decode_x509_name(issuer_der)

        self.digest_alg = decode_x509_algid(seq[2])

        offset = 3
        if len(seq) >= 6:
            assert isinstance(seq[offset], bytes)
            # The authenticated attributes are signed
            self.authenticated_attrs_raw = decode_cont_object(seq[offset], 0)  # type: ignore
            self.authenticated_attrs: Optional[Mapping[str, Any]] = \
                self._decode_attributes(self.authenticated_attrs_raw)
            offset += 1
        else:
            self.authenticated_attrs = None

        assert isinstance(seq[offset], bytes)
        self.digest_enc_alg = decode_x509_algid(seq[offset])  # type: ignore
        offset += 1
        assert isinstance(seq[offset], bytes)
        self.encrypted_digest = decode_octet_string(seq[offset])  # type: ignore
        offset += 1
        if len(seq) == 7:
            assert isinstance(seq[offset], bytes)
            raw = decode_cont_object(seq[offset], 1)  # type: ignore
            self.unauthenticated_attrs: Optional[Mapping[str, Any]] = self._decode_attributes(raw)
            offset += 1
        else:
            self.unauthenticated_attrs = None
        assert offset == len(seq)

    def _decode_attributes(self, raw: bytes) -> Mapping[str, Any]:
        """Decode authenticated or unauthenticated attributes"""
        attributes = {}
        while raw:
            attribute, raw = split_der_data(raw)
            oid_der, values_der = decode_sequence_bytes(attribute, count=2)
            oid = decode_oid(oid_der)
            values = decode_set(values_der)
            if len(values) != 1 and oid != 'szOID_NESTED_SIGNATURE':
                raise ValueError("Unexpected multiple values for attribute {} in SignerInfo".format(
                    repr(oid)))

            key: Optional[str] = None
            value: Any = None
            if oid == 'id-contentType':
                key = 'contentType'
                assert isinstance(values[0], bytes)
                value = decode_oid(values[0])
                if not self._is_timestamp_countersign:
                    if value != 'SPC_INDIRECT_DATA_OBJID':
                        raise ValueError("Unexpected contentType value in attribute of SignerInfo: {}".format(
                            repr(value)))
                else:
                    if value != 'id-ct-TSTInfo':
                        raise ValueError(
                            "Unexpected contentType in attribute of counter signed timestamp SignerInfo: {}".format(
                                repr(value)))
            elif oid == 'id-messageDigest':
                key = 'messageDigest'
                assert isinstance(values[0], bytes)
                value = decode_octet_string(values[0])
            elif oid == 'SPC_SP_OPUS_INFO_OBJID':
                key = 'spcSpOpusInfo'
                assert isinstance(values[0], bytes)
                value = AuthenticodeSpcSpOpusInfo(values[0])
            elif oid == 'SPC_STATEMENT_TYPE_OBJID':
                key = 'spcStatementType'
                assert isinstance(values[0], bytes)
                statement_type, = decode_sequence_bytes(values[0], count=1)
                value = decode_oid(statement_type)
                if value != 'SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID':
                    raise ValueError(
                        "Unexpected SPC_STATEMENT_TYPE_OBJID value in attribute of SignerInfo: {}".format(
                            repr(value)))
            elif oid == 'id-countersignature':
                # Old counter signature format
                # ... do not decode it
                key = 'counterSignature'
                assert isinstance(values[0], bytes)
                value = binascii.hexlify(values[0]).decode('ascii')
            elif oid == 'szOID_RFC3161_counterSign':
                # RFC3161: Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)
                # The value is a timestamp signed by a Time Stamping Authority (TSA)
                # ... in a PKCS#7 signedData structure, like the Authenticode signedData
                key = 'timestampCounterSign'
                assert isinstance(values[0], bytes)
                value = AuthenticodeWinCert2(values[0], is_timestamp_countersign=True)
            elif oid == 'szOID_NESTED_SIGNATURE':
                # The value is a PKCS#7 signedData structure, like the Authenticode signedData
                key = 'nestedSignature'
                value = [AuthenticodeWinCert2(val, is_timestamp_countersign=False) for val in values]  # type: ignore
            elif oid == 'szOID_PLATFORM_MANIFEST_BINARY_ID':
                assert isinstance(values[0], bytes)
                base64_value = decode_utf8_string(values[0])
                if not re.match(r'^[0-9A-Za-z+/]+=*$', base64_value):
                    raise ValueError("Unexpected szOID_PLATFORM_MANIFEST_BINARY_ID base 64 value: {}".format(
                        repr(base64_value)))
                key = 'platformManifestBinaryId'
                value = base64_value
            elif oid == 'SPC_RELAXED_PE_MARKER_CHECK_OBJID':
                key = 'spcRelaxedPEMarkerCheck'
                value = values[0]
                if not isinstance(value, int):
                    raise ValueError(
                        "Unexpected SPC_RELAXED_PE_MARKER_CHECK_OBJID value in attribute of SignerInfo: {}".format(
                            repr(value)))
            elif oid == 'sequenceNumber':
                key = 'sequenceNumber'
                value = values[0]
                if not isinstance(value, int):
                    raise ValueError(
                        "Unexpected sequenceNumber value in attribute of SignerInfo: {}".format(
                            repr(value)))
            elif self._is_timestamp_countersign and oid == 'id-aa-signingCertificate':
                # From RFC 5035 Enhanced Security Services (ESS) Update: Adding CertID Algorithm Agility
                # SigningCertificate ::= SEQUENCE {
                #     certs SEQUENCE OF ESSCertID,
                #     policies SEQUENCE OF PolicyInformation OPTIONAL
                # }
                # Ignore policies for now. Implement it only if needed.
                assert isinstance(values[0], bytes)
                certs_der, = decode_sequence_bytes(values[0], count=1)
                certs = decode_sequence_bytes(certs_der)
                # ESSCertID ::=  SEQUENCE {
                #     certHash Hash,
                #     issuerSerial IssuerSerial OPTIONAL
                # }
                cert_infos = []
                for cert_der in certs:
                    seq = decode_sequence_bytes(cert_der, counts=(1, 2))
                    cert_info: Dict[str, Union[bytes, int, str]] = {
                        'cert_hash': decode_octet_string(seq[0]),
                    }
                    if len(seq) >= 2:
                        issuer_der, serial = decode_sequence(seq[1], count=2)
                        assert isinstance(issuer_der, bytes)
                        assert isinstance(serial, int)
                        issuer_der, = decode_sequence_bytes(issuer_der, count=1)
                        issuer_der = decode_cont_object(issuer_der, 4)
                        cert_info['issuer'] = decode_x509_name(issuer_der)
                        cert_info['serial'] = serial
                    cert_infos.append(cert_info)
                key = 'signingCertificate'
                value = cert_infos
            elif self._is_timestamp_countersign and oid == 'id-aa-signingCertificateV2':
                # From RFC 5035 Enhanced Security Services (ESS) Update: Adding CertID Algorithm Agility
                # SigningCertificateV2 ::=  SEQUENCE {
                #     certs SEQUENCE OF ESSCertIDv2,
                #     policies SEQUENCE OF PolicyInformation OPTIONAL
                # }
                # Ignore policies for now. Implement it only if needed.
                assert isinstance(values[0], bytes)
                certs_der, = decode_sequence_bytes(values[0], count=1)
                certs = decode_sequence_bytes(certs_der)
                # ESSCertIDv2 ::=  SEQUENCE {
                #     hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
                #     certHash Hash,
                #     issuerSerial IssuerSerial OPTIONAL
                # }
                cert_infos = []
                for cert_der in certs:
                    seq = decode_sequence_bytes(cert_der, counts=(1, 2))
                    cert_info = {
                        'cert_hash': decode_octet_string(seq[0]),
                    }
                    if len(seq) >= 2:
                        issuer_der, serial = decode_sequence(seq[1], count=2)
                        assert isinstance(issuer_der, bytes)
                        assert isinstance(serial, int)
                        issuer_der, = decode_sequence_bytes(issuer_der, count=1)
                        issuer_der = decode_cont_object(issuer_der, 4)
                        cert_info['issuer'] = decode_x509_name(issuer_der)
                        cert_info['serial'] = serial
                    cert_infos.append(cert_info)
                key = 'signingCertificateV2'
                value = cert_infos
            elif self._is_timestamp_countersign and oid == 'id-signingTime':
                # ASN.1 UTCTIME + Format "YYYYmmddHHMMSSZ"
                assert isinstance(values[0], bytes)
                if len(values[0]) != 0xf or not values[0].startswith(b'\x17\x0d') or not values[0].endswith(b'Z'):
                    raise ValueError("Unexpected value for attribute {}: {}".format(repr(oid), repr(values[0])))
                key = 'signingTime'
                value = str(datetime.datetime.strptime(values[0][2:-1].decode('ascii'), '%y%m%d%H%M%S'))
            else:
                logger.warning("Unknown attribute OID %r in SignerInfo", oid)
                key = oid
                if isinstance(values[0], bytes):
                    value = binascii.hexlify(values[0]).decode('ascii')
                else:
                    value = values[0]

            assert key
            assert value is not None

            if key in attributes:
                raise ValueError("Duplicated attribute {}->{} in SignerInfo".format(
                    repr(oid), repr(key)))
            attributes[key] = value
        return attributes

    def to_dict_description(self) -> Mapping[str, Union[str, int, Dict[str, Any]]]:
        """Convert to a dictionary describing the object"""
        result: Dict[str, Union[str, int, Dict[str, Any]]] = {
            'issuer': self.issuer,
            'serial_number': self.serial_number,
            'digest_alg': self.digest_alg,
        }
        if self.authenticated_attrs:
            authenticated_attrs_desc: Dict[str, Any] = {}
            for key, value in self.authenticated_attrs.items():
                if key == 'messageDigest':
                    value = binascii.hexlify(value).decode('ascii')
                elif key == 'spcSpOpusInfo':
                    value = value.to_dict_description()
                elif self._is_timestamp_countersign and key in ('signingCertificate', 'signingCertificateV2'):
                    value = value.copy()
                    for cert in value:
                        cert['cert_hash'] = binascii.hexlify(cert['cert_hash']).decode('ascii')
                authenticated_attrs_desc[key] = value
            result['authenticated_attrs'] = authenticated_attrs_desc

        result['digest_enc_alg'] = self.digest_enc_alg
        result['encrypted_digest'] = '({} bytes)'.format(len(self.encrypted_digest))
        if self.unauthenticated_attrs:
            unauthenticated_attrs_desc: Dict[str, Any] = {}
            for key, value in self.unauthenticated_attrs.items():
                if key == 'timestampCounterSign':
                    value = value.to_dict_description()
                elif key == 'nestedSignature':
                    value = [val.to_dict_description() for val in value]
                unauthenticated_attrs_desc[key] = value
            result['unauthenticated_attrs'] = unauthenticated_attrs_desc
        return result


class AuthenticodeSignedData:
    """Authenticode SignedData

    ASN.1 structure:
        SignedData ::= SEQUENCE {
            version Version,
            digestAlgorithms DigestAlgorithmIdentifiers,
            contentInfo ContentInfo,
            certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
            Crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
            signerInfos SignerInfos
        }
        DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
        SignerInfos ::= SET OF SignerInfo
    """
    def __init__(self, der_content: bytes, is_timestamp_countersign: bool = False):
        seq = decode_sequence(der_content, counts=(4, 5, 6))
        assert isinstance(seq[0], int)
        assert isinstance(seq[1], bytes)
        assert isinstance(seq[2], bytes)

        self.version = seq[0]
        if not is_timestamp_countersign:
            if self.version != 1:
                raise ValueError("Unexpected version in Authenticode SignedData: {}".format(
                    repr(self.version)))
        elif self.version != 3:
            raise ValueError("Unexpected version in counter signed timestamp SignedData: {}".format(
                repr(self.version)))

        digest_algs_set = decode_set_bytes(seq[1])
        if len(digest_algs_set) != 1:
            raise ValueError("Unexpected number of digestAlgorithms in SignedData: {}".format(
                repr(digest_algs_set)))
        self.digest_alg = decode_x509_algid(digest_algs_set[0])

        self.content_info = AuthenticodeContentInfo(
            seq[2], is_timestamp_countersign=is_timestamp_countersign)

        if len(seq) >= 5:
            assert isinstance(seq[3], bytes)
            certificates_der = decode_cont_object(seq[3], 0)

            # Certificates are concatenated
            self.certificates: Optional[List[bytes]] = []
            self.cert_descriptions: Optional[List[Mapping[str, Union[int, str]]]] = []
            while certificates_der:
                cert, certificates_der = split_der_data(certificates_der)
                self.certificates.append(cert)
                if cert[0] != 0x30:
                    # There might be a continuation tag to indicate something,
                    # and this happens in timestamp counter signing certificate.
                    if cert[0] == 0xa1:
                        self.cert_descriptions.append({"error": "(certificate cont[1])"})
                        continue
                    raise ValueError("Unexpected ASN.1 tag for certificate in SignedData: {}".format(
                        repr(cert)))
                desc = describe_der_certificate(cert)
                self.cert_descriptions.append(desc)
        else:
            self.certificates = None
            self.cert_descriptions = None

        if len(seq) >= 6:
            raise ValueError("Found CRL in SignedData even though it is supposed not to be used: {}".format(
                repr(seq[4])))

        assert isinstance(seq[-1], bytes)
        signer_infos_set = decode_set_bytes(seq[-1])
        if len(signer_infos_set) != 1:
            raise ValueError("Unexpected number of signerInfos in SignedData: {}".format(
                repr(signer_infos_set)))
        self.signer_info = AuthenticodeSignerInfo(
            signer_infos_set[0],
            is_timestamp_countersign=is_timestamp_countersign)

    def to_dict_description(self) -> Mapping[str, Any]:
        """Convert to a dictionary describing the object"""
        result: Dict[str, Any] = {
            'digest_alg': self.digest_alg,
            'content_info': self.content_info.to_dict_description(),
        }
        if self.certificates:
            result['certificates'] = self.cert_descriptions
        result['signer_infos'] = self.signer_info.to_dict_description()
        return result


class AuthenticodeWinCert2:
    """Authenticode Win_Certificate Version 2 with SignedData

    The Authenticode signature in a PE file is in a PKCS #7 SignedData structure.
    It is indicated by certificate type WIN_CERT_TYPE_PKCS_SIGNED_DATA = 2.

    ASN.1 structure:
    SEQUENCE {
        oid OBJECT IDENTIFIER,
        SignedData [0] IMPLICIT SignedData,
    }
    """
    def __init__(self, der_content: bytes, is_timestamp_countersign: bool = False):
        """Load a Certificate from DER-encoded content"""
        # Remove the padding after the sequence
        if der_content[0] != 0x30:
            raise ValueError("Authenticode SignedData is not an ASN.1 sequence: type={:#x}".format(der_content[0]))

        # Ensure that the padding only contains null bytes
        der_content, padding = split_der_data(der_content)
        if any(x != 0 for x in padding):
            raise ValueError("Unexpected non-null padding in Authenticode SignedData: {}".format(
                repr(padding)))

        oid_der, signed_data_der = decode_sequence_bytes(der_content, count=2)
        oid = decode_oid(oid_der)
        if oid != 'pkcs7-signedData':
            raise ValueError("Unexpected signedData OID, got {}".format(oid))
        signed_data_der = decode_cont_object(signed_data_der, 0)
        self.data = AuthenticodeSignedData(
            signed_data_der, is_timestamp_countersign=is_timestamp_countersign)

    def to_dict_description(self) -> Mapping[str, Any]:
        """Convert to a dictionary describing the object"""
        return self.data.to_dict_description()


if __name__ == '__main__':
    from pathlib import Path
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    import pe_structs

    logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)
    for file_path in sys.argv[1:]:
        pe_file = pe_structs.PEFile(Path(file_path))
        signatures = pe_file.signatures
        if not signatures:
            logger.warning("No Authenticode signature found in %s", file_path)
            continue

        print("{}:".format(file_path))
        print("  * {} PKCS#7 SignedData structure(s)".format(len(signatures)))
        for idx, signature in enumerate(signatures):
            print("    [{}]:".format(idx))
            pe_structs.dump_dict(signature.to_dict_description(), indent='      ')
