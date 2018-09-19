#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2018 Nicolas Iooss
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
"""Find a RSA modulus from PKCS#1 v1.5 signatures

Input file format: one signature per line, with "HASH MESSAGE SIGNATURE",
separated by spaces. HASH can be RAW, MD5, SHA1, SHA224 SHA256, SHA384 or SHA512,
and MESSAGE and SIGNATURE are represented in hexadecimal.


Benchmark (the duration is quadratic to the number of bits of N):

* RSA 1024: 5 hours 12 minutes with GCD:

    10:48:35 [INFO] Computing first N
    10:50:02 [INFO] Reduced N by 2, 67006181 bits remaining
    10:50:03 [INFO] Reduced N by 29, 67006176 bits remaining
    10:50:48 [INFO] Iteration 1: N has 67006176 bits
    10:52:15 [INFO] Performing a GCD with a 66784366-bit number
    16:00:39 [INFO] Reduced N to 1024 bits

* RSA 1024: 3 days 17 hours 45 minutes without GCD
  (approx. 39000000 iterations)

* RSA 2048: 19 hours 32 minutes with GCD:

    16:26:03 [INFO] Computing first N
    16:30:29 [INFO] Reduced N by 2, 134096885 bits remaining
    16:31:59 [INFO] Message 1/10: N has 134096885 bits
    16:37:15 [INFO] Performing a GCD with a 134096883-bit number
    (next day)
    12:09:42 [INFO] Reduced N to 2048 bits

@author: Nicolas Iooss
@license: MIT
"""
import argparse
import base64
import binascii
import errno
import json
import hashlib
import logging
import math
import re
import struct
import sys

try:
    import Crypto.Signature.PKCS1_v1_5
    has_crypto = True
except ImportError:
    # pypy for example does not provide PyCrypto
    has_crypto = False
else:
    import Crypto.PublicKey.RSA
    import Crypto.Hash.MD5
    import Crypto.Hash.SHA
    import Crypto.Hash.SHA224
    import Crypto.Hash.SHA256
    import Crypto.Hash.SHA384
    import Crypto.Hash.SHA512
    import Crypto.Util.asn1


logger = logging.getLogger(__name__)


def xx(data):
    return binascii.hexlify(data).decode('ascii')


def unxx(data):
    return binascii.unhexlify(data)


def b64url_decode(data):
    """Decode data encoded as base64-URL"""
    datalen = len(data)
    # Recover base64 padding
    if datalen % 4 == 3:
        data += '='
    elif datalen % 4 == 2:
        data += '=='
    return base64.b64decode(data, altchars='-_')


def decode_bigint_be(data):
    """Decode a Big-Endian big integer"""
    return int(binascii.hexlify(data).decode('ascii'), 16)


def encode_bigint_be(value, bytelen=None):
    """Encode a Big-Endian big integer"""
    if bytelen is None:
        bytelen = (value.bit_length() + 7) // 8
    hexval = '{{:0{:d}x}}'.format(bytelen * 2).format(value)
    return binascii.unhexlify(hexval.encode('ascii'))


class ModulusSaveFile(object):
    """File where to save intermediate computation results"""
    def __init__(self, filepath):
        self.filepath = filepath
        if not filepath:
            logger.warning("The intermediate results will NOT be saved")

    def load(self):
        """Load a file which contains intermediate computation results"""
        if not self.filepath:
            return None
        modulus = None
        try:
            with open(self.filepath, 'r') as fmodulus:
                for lineno, line in enumerate(fmodulus):
                    if not line.endswith('\n'):
                        logger.warning("Found truncated line %d in saved file. Please remove it", lineno + 1)
                        raise ValueError("Truncated line found in saved file")
                    new_modulus = int(line, 16)
                    if new_modulus < 2:
                        logger.fatal("Found invalid modulus line %d (%d) in saved file", lineno + 1, new_modulus)
                        raise ValueError("Invalid saved file")
                    if modulus and modulus % new_modulus:
                        logger.warning("Modulus on line %d does not divide the previous ones", lineno + 1)
                        # Skip the invalide modulus
                    else:
                        modulus = new_modulus
            logger.info("Loaded %d bits from %s", modulus.bit_length(), self.filepath)
            return modulus
        except IOError as exc:
            if exc.errno == errno.ENOENT:
                logger.info("No saved file found. Starting from nothing")
                return None
            raise

    def save_intermediate(self, modulus, verbose=True):
        """Save an intermediate value in the modulus computation"""
        if not self.filepath:
            return
        with open(self.filepath, 'a') as fmodulus:
            fmodulus.write('{:x}\n'.format(modulus))
        if verbose:
            logger.info("Saved %d bits into %s", modulus.bit_length(), self.filepath)


# Supported kind of digests, with PKCS#1 v1.5 prefixes
# Some acronyms for Object Identifiers (OID):
# * CSOR = Computer Security Objects Register
# * ISO = International Organization for Standardization
# * ITU-T = ITU Telecommunication Standardization Sector
# * OIW = OSE Implementors' Workshop
# * OIW/SECSIG = OIW Security Special Interest Group
# * OSE = Open Systems Environment
DIGEST_ASN1_PREFIXES = {
    # ASN.1 {{OID 1.2.840.113549.2.5:md5, NULL}, OCTET STRING[16]}
    # OID iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) md5(5)
    'MD5': '3020300c06082a864886f70d020505000410',

    # ASN.1 {{OID 1.3.14.3.2.26:sha1, NULL}, OCTET STRING[20]}
    # OID iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) hashAlgorithmIdentifier(26)
    'SHA1': '3021300906052b0e03021a05000414',

    # ASN.1 {{OID 2.16.840.1.101.3.4.2.4:sha224, NULL}, OCTET STRING[28]}
    # OID joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha224(4)
    'SHA224': '302d300d06096086480165030402040500041c',

    # ASN.1 {{OID 2.16.840.1.101.3.4.2.1:sha256, NULL}, OCTET STRING[32]}
    # OID joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha256(1)
    'SHA256': '3031300d060960864801650304020105000420',

    # ASN.1 {{OID 2.16.840.1.101.3.4.2.2:sha384, NULL}, OCTET STRING[48]}
    # OID joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha384(2)
    'SHA384': '3041300d060960864801650304020205000430',

    # ASN.1 {{OID 2.16.840.1.101.3.4.2.3:sha512, NULL}, OCTET STRING[64]}
    # OID joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha512(3)
    'SHA512': '3051300d060960864801650304020305000440',
}

DIGEST_HASHLIB = {
    'MD5': hashlib.md5,
    'SHA1': hashlib.sha1,
    'SHA224': hashlib.sha224,
    'SHA256': hashlib.sha256,
    'SHA384': hashlib.sha384,
    'SHA512': hashlib.sha512,
}


def encapsulate_pcks1v15_digest(kind, message, bits):
    """Transform digests into PKCS#1 v1.5 with the specified bit size"""
    assert bits % 8 == 0
    pkcs_asn1_prefix = DIGEST_ASN1_PREFIXES[kind]
    digest = DIGEST_HASHLIB[kind](message).digest()
    pkcs1_15_digest = binascii.unhexlify(pkcs_asn1_prefix) + digest
    pkcs1_15_padding = b'\xff' * (bits // 8 - 3 - len(pkcs1_15_digest))
    result = b'\x00\x01' + pkcs1_15_padding + b'\x00' + pkcs1_15_digest
    assert len(result) * 8 == bits
    return result


def hash_algorithm(alg, allow_raw=False):
    """Parse an hash algorithm"""
    # canonical name: only alpha-numeric uppercase characters
    alg = re.sub(r'[^0-9A-Z]', '', alg.upper())
    if alg in DIGEST_ASN1_PREFIXES:
        return alg
    elif allow_raw and alg == 'RAW':
        return alg
    raise ValueError("Unknown hash algorithm {}".format(alg))


def show_jwt(jwt, show_raw=False):
    """Decode a JWT according to https://tools.ietf.org/html/rfc7519"""
    # JSON web tokens have three parts: header, payload and signature.
    # A JWT may have only two parts if it is not signed ("alg=none").
    jwt = jwt.strip()
    jwt_parts = jwt.split('.')
    if len(jwt_parts) != 3:
        logger.error("Syntax error in JWT token: only %d parts", len(jwt_parts))
        return False
    jwt_header = json.loads(b64url_decode(jwt_parts[0]))
    jwt_type = jwt_header.get('typ', '(no type)')
    jwt_alg = jwt_header.get('alg')
    if not jwt_alg:
        logger.error("No signature algorithm in JWT header %r", jwt_header)
        return False
    m = re.match(r'^RS(256|384|512)$', jwt_alg)
    if not m:
        logger.error("Non-RSA JWT signature algorithm %r", jwt_alg)
        return False

    hash_kind = hash_algorithm('SHA' + m.group(1))
    msg = jwt.rsplit('.', 1)[0].encode('ascii')
    jwt_signature = b64url_decode(jwt_parts[2])
    bits = len(jwt_signature) * 8

    if show_raw:
        # Encapsulate the hash into the displayed message
        msg = encapsulate_pcks1v15_digest(hash_kind, msg, bits)
        hash_kind = 'RAW'

    print("# {} RSA-{:d} + SHA-{} {}".format(jwt_type, bits, m.group(1), jwt))
    print("{} {} {}".format(hash_kind, xx(msg), xx(jwt_signature)))
    return True


def decode_x509_dn(asn1_der_dn):
    """Decode a DER-encoded ASN.1 Distinguished Name (DN)

    A DN is used to identify the subject and the issuer of an X.509 certificate.
    """
    dn_asn1 = Crypto.Util.asn1.DerSequence()
    dn_asn1.decode(asn1_der_dn)
    dn_parts = []
    for dn_asn1_part in dn_asn1:
        # Decode SET (tag 0x31 = constructed tag 0x11)
        dn_set_item = Crypto.Util.asn1.DerObject(asn1Id=0x11, constructed=True)
        dn_set_item.decode(dn_asn1_part)
        dn_set_seq = Crypto.Util.asn1.DerSequence()
        dn_set_seq.decode(dn_set_item.payload)
        if len(dn_set_seq) != 2:
            logger.warning("Unexpected ASN.1 DN construction %s", xx(dn_set_item.payload))
            # Fail-over by directly inserting the ill-formated item
            dn_parts.append(xx(dn_set_item.payload))
            continue
        der_oid, der_value = dn_set_seq[:]
        der_oid_hex = xx(der_oid)
        if der_oid_hex == '060a0992268993f22c640101':
            # OID 0.9.2342.19200300.100.1.1
            # itu-t(0) data(9) pss(2342) ucl(19200300) pilot(100) pilotAttributeType(1) userid(1)
            item_key = 'UID'
        elif der_oid_hex == '0603550403':
            # OID 2.5.4.3
            # joint-iso-itu-t(2) ds(5) attributeType(4) commonName(3)
            item_key = 'CN'
        elif der_oid_hex == '0603550405':
            # OID 2.5.4.5
            # joint-iso-itu-t(2) ds(5) attributeType(4) serialNumber(5)
            item_key = 'SN'
        elif der_oid_hex == '0603550406':
            # OID 2.5.4.6
            # joint-iso-itu-t(2) ds(5) attributeType(4) countryName(6)
            item_key = 'C'
        elif der_oid_hex == '0603550407':
            # OID 2.5.4.7
            # joint-iso-itu-t(2) ds(5) attributeType(4) localityName(7)
            item_key = 'L'
        elif der_oid_hex == '0603550408':
            # OID 2.5.4.8
            # joint-iso-itu-t(2) ds(5) attributeType(4) stateOrProvinceName(8)
            item_key = 'ST'
        elif der_oid_hex == '0603550409':
            # OID 2.5.4.9
            # joint-iso-itu-t(2) ds(5) attributeType(4) streetAddress(9)
            item_key = 'STREET'
        elif der_oid_hex == '060355040a':
            # OID 2.5.4.10
            # joint-iso-itu-t(2) ds(5) attributeType(4) organizationName(10)
            item_key = 'O'
        elif der_oid_hex == '060355040b':
            # OID 2.5.4.11
            # joint-iso-itu-t(2) ds(5) attributeType(4) organizationalUnitName(11)
            item_key = 'OU'
        else:
            # Build the OID from der_oid
            oid_asn1 = Crypto.Util.asn1.DerObjectId()
            oid_asn1.decode(der_oid)
            item_key = oid_asn1.value
            logger.warning("Unknown DN component OID %s (%s)", item_key, der_oid_hex)

        value_asn1 = Crypto.Util.asn1.DerObject()
        value_asn1.decode(der_value)
        item_value = value_asn1.payload.decode('utf-8', errors='replace')
        dn_parts.append("{}={}".format(
            item_key,
            item_value if re.match(r'^[0-9a-zA-Z._-]+$', item_value) else repr(item_value)))
    return '/'.join(dn_parts)


def show_pemfile(pemfile, show_raw=False):
    """Extract a signature from an X.509 certificate in PEM format

    The format of an X.509 certificate is described in "Appendix A: ASN.1 Syntax
    for Certificates and CRLs" for RFC 1422 "Certificate-Based Key Management":
    https://tools.ietf.org/html/rfc1422#appendix-A
    """
    with open(pemfile, 'rb') as fpem:
        pem_lines = fpem.readlines()
    try:
        begin_index = pem_lines.index(b'-----BEGIN CERTIFICATE-----\n')
    except ValueError:
        logger.error("Unable to find a certificate section in %s", pemfile)
        return False
    try:
        end_index = pem_lines.index(b'-----END CERTIFICATE-----\n', begin_index)
    except ValueError:
        logger.error("Unable to find the end of a certificate section in %s", pemfile)
        return False
    der_certificate = base64.b64decode(b''.join(pem_lines[begin_index + 1:end_index]))
    cert_asn1 = Crypto.Util.asn1.DerSequence()
    cert_asn1.decode(der_certificate)
    # The certificate is in 3 parts: signed information, algorithm ID, signature
    if len(cert_asn1) != 3:
        logger.error("Invalid ASN.1 SIGNED SEQUENCE structure in certificate %s", pemfile)
        return False
    der_signed_information, der_algorithm_ident, der_signature = cert_asn1[:]

    # https://tools.ietf.org/html/rfc1423#section-4.2.1
    # The ASN.1 type AlgorithmIdentifier is defined in X.509 as follows.
    # AlgorithmIdentifier ::= SEQUENCE {
    #     algorithm         OBJECT IDENTIFIER,
    #     parameters        ANY DEFINED BY algorithm OPTIONAL
    # }
    algorithm_ident_asn1 = Crypto.Util.asn1.DerSequence()
    algorithm_ident_asn1.decode(der_algorithm_ident)
    if len(algorithm_ident_asn1) != 2:
        # This may occur when using ecdsa-with-SHA256 signature (1 component)
        logger.error("Invalid ASN.1 AlgorithmIdentifier structure in %s (%d components)",
                     pemfile, len(algorithm_ident_asn1))
        return False
    algo_id, algo_params = algorithm_ident_asn1[:]
    # AlgorithmIdentifier.parameters is NULL
    if algo_params != b'\x05\x00':
        logger.error("Unexpected AlgorithmIdentifier.parameters in %s: %s", pemfile, xx(algo_params))
        return False
    hex_algo_id = xx(algo_id)
    if hex_algo_id == '06092a864886f70d010104':
        # OBJECT IDENTIFIER 1.2.840.113549.1.1.4 md5WithRSAEncryption
        # OID iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) md5WithRSAEncryption(5)
        hash_kind = 'MD5'
    elif hex_algo_id == '06092a864886f70d010105':
        # OBJECT IDENTIFIER 1.2.840.113549.1.1.5 sha1WithRSAEncryption
        # OID iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha1-with-rsa-signature(5)
        hash_kind = 'SHA1'
    elif hex_algo_id == '06092a864886f70d01010b':
        # OBJECT IDENTIFIER 1.2.840.113549.1.1.11 sha256WithRSAEncryption
        # OID iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha256WithRSAEncryption(11)
        hash_kind = 'SHA256'
    elif hex_algo_id == '06092a864886f70d01010c':
        # OBJECT IDENTIFIER 1.2.840.113549.1.1.12 sha384WithRSAEncryption
        # OID iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha384WithRSAEncryption(12)
        hash_kind = 'SHA384'
    elif hex_algo_id == '06092a864886f70d01010d':
        # OBJECT IDENTIFIER 1.2.840.113549.1.1.13 sha512WithRSAEncryption
        # OID iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha512WithRSAEncryption(13)
        hash_kind = 'SHA512'
    elif hex_algo_id == '06092a864886f70d01010e':
        # OBJECT IDENTIFIER 1.2.840.113549.1.1.14 sha224WithRSAEncryption
        # OID iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha224WithRSAEncryption(14)
        hash_kind = 'SHA224'
    else:
        logger.error("Unknown signature algorithm identifier in %s: %s", pemfile, hex_algo_id)
        # Show the decoded OID when an error happens
        algo_oid = Crypto.Util.asn1.DerObjectId()
        algo_oid.decode(algo_id)
        logger.error("... algorithm OID is %r", algo_oid.value)
        return False

    # The signature is a BIT STRING
    signature_asn1 = Crypto.Util.asn1.DerBitString()
    signature_asn1.decode(der_signature)
    signature = signature_asn1.value
    bits = len(signature) * 8
    logger.debug("Read a RSA-%d signature with digest %s from %s", bits, hash_kind, pemfile)

    # Decode the issuer from the certificate
    signed_info_asn1 = Crypto.Util.asn1.DerSequence()
    signed_info_asn1.decode(der_signed_information)
    # https://tools.ietf.org/html/rfc1422#appendix-A.1
    # Certificate ::= SIGNED SEQUENCE{
    #       version [0]     Version DEFAULT v1988,
    #       serialNumber    CertificateSerialNumber,
    #       signature       AlgorithmIdentifier,
    #       issuer          Name,
    #       validity        Validity,
    #       subject         Name,
    #       subjectPublicKeyInfo    SubjectPublicKeyInfo}
    if len(signed_info_asn1) < 6:
        logger.error("Not enough fields in certificate %s (%d < 6)", pemfile, len(signed_info_asn1))
        return False
    # Sometimes the version can be missing, in which case the second item is a sequence instead of an int
    if isinstance(signed_info_asn1[1], bytes):
        if isinstance(signed_info_asn1[0], bytes):
            logger.error("Unexpected construction of X.509 certificate %s", pemfile)
            return False
        # Add a "fake" version field
        signed_info_asn1 = list(signed_info_asn1)
        signed_info_asn1.insert(0, None)
    if len(signed_info_asn1) < 7:
        logger.error("Not enough fields in certificate %s (%d < 7)", pemfile, len(signed_info_asn1))
        return False

    issuer_dn = decode_x509_dn(signed_info_asn1[3])
    subject_dn = decode_x509_dn(signed_info_asn1[5])
    if issuer_dn == subject_dn:
        # Allow specifying a self-signed certificate in order to test the program
        logger.info("Certificate %s is self-signed. Verifying the signature", pemfile)
        public_key_der = signed_info_asn1[6]
        pubkey = Crypto.PublicKey.RSA.importKey(public_key_der)

        encrypted_num = decode_bigint_be(signature)
        signed_data = encapsulate_pcks1v15_digest(hash_kind, der_signed_information, bits)
        clear_num = decode_bigint_be(signed_data)
        if clear_num != pow(encrypted_num, pubkey.e, pubkey.n):
            logger.error("The signature of self-signed certificate %s is incorrect", pemfile)
        else:
            print("# KEY_N = {:#x}".format(pubkey.n))
            print("# KEY_E = {:#x}".format(pubkey.e))

    print("# {}+RSA-{:d} signature by {} for {}".format(hash_kind, bits, issuer_dn, subject_dn))
    if show_raw:
        # Encapsulate the hash into the displayed message
        msg = encapsulate_pcks1v15_digest(hash_kind, der_signed_information, bits)
        hash_kind = 'RAW'
    else:
        msg = der_signed_information
    print("{} {} {}".format(hash_kind, xx(msg), xx(signature)))
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description="Find a RSA modulus")
    parser.add_argument('file', metavar="FILEPATH", nargs='?', type=str,
                        help="file which holds hexadecimal signatures, one per line")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-e', '--exponent', type=int, default=0x10001,
                        help="RSA exponent to use (default 0x10001=65537)")
    parser.add_argument('-m', '--math-gcd', action='store_true',
                        help="use math.gcd")
    parser.add_argument('-s', '--savefile', type=str,
                        help="file which holds saved intermediate results")
    parser.add_argument('-j', '--jwt', type=str, action='append',
                        help="Convert JWT (JSON Web Tokens) to signatures")
    parser.add_argument('-P', '--pem', type=str, action='append',
                        help="Convert signed certificates in PEM format to signatures")
    parser.add_argument('-g', '--generate-count', type=int,
                        help="generate a key and sign the given number of messages")
    parser.add_argument('-b', '--bits', type=int,
                        help="size of the generated RSA key, in bits (default 2048)")
    parser.add_argument('-H', '--hash', type=hash_algorithm, default='SHA1',
                        help="hash algorithm to use when genrating messages (default SHA1)")
    parser.add_argument('-R', '--raw', action='store_true',
                        help="show raw PKCS#1 v1.5 cleartextes instead of hashed messages")
    args = parser.parse_args(argv)

    # Log with the date, because computations can last several days
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.DEBUG if args.debug else logging.INFO,
    )

    if args.jwt:
        retval = 0
        for jwt in args.jwt:
            if not show_jwt(jwt, show_raw=args.raw):
                retval = 1
        return retval

    if args.pem:
        if not has_crypto:
            logger.fatal("Using --pem requires PyCrypto")
            return 1
        retval = 0
        for pemfile in args.pem:
            if not show_pemfile(pemfile, show_raw=args.raw):
                retval = 1
        return retval

    if args.generate_count:
        if args.generate_count < 2:
            parser.error("need at least 2 tests to generate")
        if not has_crypto:
            logger.fatal("Unable to import pyCrypto, needed to generate a key")
            return 1
        bits = args.bits or 2048
        key = Crypto.PublicKey.RSA.generate(bits)
        print("# KEY_N = {:#x}".format(key.n))
        print("# KEY_E = {:#x}".format(key.e))
        print("# KEY_D = {:#x}".format(key.d))
        print("# KEY_P = {:#x}".format(key.p))
        print("# KEY_Q = {:#x}".format(key.q))
        if key.e != args.exponent:
            parser.error("generated key does not use the given exponent")

        # Sign messages
        hash_kind = args.hash
        if hash_kind == 'SHA1':
            # Old versions of PyCrypto use Crypto.Hash.SHA instead of Crypto.Hash.SHA1
            hash_class = Crypto.Hash.SHA
        else:
            hash_class = getattr(Crypto.Hash, hash_kind)
        for i in range(args.generate_count):
            msg = struct.pack('>Q', i)
            engine = Crypto.Signature.PKCS1_v1_5.new(key)
            signature = engine.sign(hash_class.new(msg))
            clear_signature = encode_bigint_be(
                pow(decode_bigint_be(signature), key.e, key.n),
                bits // 8)

            # Transform the digest of the message into PKCS#1 v1.5
            pkcs1_15_digest = encapsulate_pcks1v15_digest(hash_kind, msg, bits)
            assert clear_signature == pkcs1_15_digest
            clear_num = decode_bigint_be(pkcs1_15_digest)
            encrypted_num = pow(clear_num, key.d, key.n)
            assert signature == encode_bigint_be(encrypted_num, bits // 8)

            if args.raw:
                print("# {} {}".format(hash_kind, xx(msg)))
                print("RAW {} {}".format(xx(pkcs1_15_digest), xx(signature)))
            else:
                print("{} {} {}".format(hash_kind, xx(msg), xx(signature)))
        return 0

    if not args.file:
        parser.error("no signature file given. You may use '-g 10' to generate one")

    # Load signatures
    bits = args.bits
    debug_gen_key_n = None
    msg_and_signatures = []
    with open(args.file) as fsignatures:
        for lineno, line in enumerate(fsignatures):
            # Recover KEY_N from the generated file, in order to ease debugging
            if line.startswith('# KEY_N = 0x'):
                debug_gen_key_n = int(line[len('# KEY_N = 0x'):], 16)
                logger.info("Loading a generated N for debugging, %d bits", debug_gen_key_n.bit_length())
                if bits and bits != debug_gen_key_n.bit_length():
                    logger.error("Mismatching size with bits parameter (%d)", bits)
                    return 1
            if '#' in line:
                # Remove comments
                line = line.split('#', 1)[0]
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 3:
                logger.error("Unable to parse line %d of signature file (%d parts)",
                             lineno + 1, len(parts))
                return 1
            hash_kind = hash_algorithm(parts[0], allow_raw=True)
            msg = unxx(parts[1])
            signature = unxx(parts[2])
            if not bits:
                bits = len(signature) * 8
            elif len(signature) * 8 != bits:
                logger.error(
                    "Signature size does not match (%d vs %d)",
                    len(signature) * 8, bits)
                return 1
            elif hash_kind == 'RAW' and len(msg) * 8 != bits:
                logger.error(
                    "Raw message size of line %d does not match (%d vs %d)",
                    lineno + 1, len(msg) * 8, bits)
                return 1
            msg_and_signatures.append((hash_kind, msg, signature))

    if not msg_and_signatures:
        logger.error("File %s is empty", args.file)
        return 1

    if args.raw:
        # Show raw PKCS#1 v1.5-encapsulated digests
        if debug_gen_key_n:
            # Keep the debugging N, if provided
            print("# KEY_N = {:#x}".format(debug_gen_key_n))
        for hash_kind, msg, signature in msg_and_signatures:
            pkcs1_15_digest = encapsulate_pcks1v15_digest(hash_kind, msg, bits)
            print("# {} {}".format(hash_kind, xx(msg)))
            print("RAW {} {}".format(xx(pkcs1_15_digest), xx(signature)))
        return 0

    logger.info("Loaded %d %d-bit signatures", len(msg_and_signatures), bits)

    # Restore a previously found modulus
    save_file = ModulusSaveFile(args.savefile)
    current_modulus = save_file.load()

    # Start the computation
    for iter_count, msg_signature in enumerate(msg_and_signatures):
        hash_kind, msg, signature = msg_signature

        # Transform digests into PKCS#1 v1.5
        if hash_kind == 'RAW':
            pkcs1_15_digest = msg
        else:
            pkcs1_15_digest = encapsulate_pcks1v15_digest(hash_kind, msg, bits)
        assert len(pkcs1_15_digest) * 8 == bits
        clear_num = decode_bigint_be(pkcs1_15_digest)
        encrypted_num = decode_bigint_be(signature)

        # Check construction
        if debug_gen_key_n:
            assert encrypted_num < debug_gen_key_n
            assert pow(encrypted_num, args.exponent, debug_gen_key_n) == clear_num

        # First iteration
        if not current_modulus:
            logger.info("Computing first N (message using %s)", hash_kind)
            current_modulus = pow(encrypted_num, args.exponent) - clear_num
            assert not debug_gen_key_n or current_modulus % debug_gen_key_n == 0  # sanity check
            # Factorize by small numbers
            for factor in range(2, 1000):
                while (current_modulus % factor) == 0:
                    current_modulus = current_modulus // factor
                    logger.info("Reduced N by %d, %d bits remaining", factor, current_modulus.bit_length())

        else:
            # Processing new mesage
            new_n = pow(encrypted_num, args.exponent, current_modulus) - clear_num
            if new_n == 0:
                logger.info(
                    "Message %d/%d (%s): new N = zero mod current N, skipping",
                    iter_count + 1, len(msg_and_signatures), hash_kind)
                continue
            if new_n < 0:
                new_n += current_modulus
            assert not debug_gen_key_n or current_modulus % debug_gen_key_n == 0  # sanity check
            logger.info("Performing a GCD with a %d-bit number", new_n.bit_length())
            if args.math_gcd:
                # May take several hours without visibility
                current_modulus = math.gcd(current_modulus, new_n)
                logger.info("Reduced N to %d bits", current_modulus.bit_length())
            else:
                # ... with visibility
                iter_gcd = 0
                while new_n != 0:
                    assert 0 <= new_n <= current_modulus  # sanity check
                    tmp = current_modulus % new_n
                    current_modulus = new_n
                    new_n = tmp
                    iter_gcd += 1
                    if not (iter_gcd % 100000):
                        logger.debug("%d iterations: N has %d bits", iter_gcd, current_modulus.bit_length())
                        save_file.save_intermediate(current_modulus, verbose=False)

                logger.info("Reduced N to %d bits (%d iterations)", current_modulus.bit_length(), iter_gcd)
            for factor in range(2, 1000):
                while (current_modulus % factor) == 0:
                    current_modulus = current_modulus // factor
                    logger.info("Reduced N by %d: N has %d bits", factor, current_modulus.bit_length())

        save_file.save_intermediate(current_modulus)
        assert not debug_gen_key_n or current_modulus % debug_gen_key_n == 0  # sanity check
        logger.info(
            "Message %d/%d (%s): N has %d bits",
            iter_count + 1, len(msg_and_signatures), hash_kind, current_modulus.bit_length())

    logger.info("END. N has %d bits: %#x", current_modulus.bit_length(), current_modulus)

    # Show the public key as a PEM certificate, if PyCrypto is available
    if has_crypto and current_modulus.bit_length() >= 512:
        public_key = Crypto.PublicKey.RSA.construct((current_modulus, args.exponent))
        print("Public key in PEM format:")
        print(public_key.exportKey('PEM').decode('ascii'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
