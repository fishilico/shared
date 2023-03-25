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
"""Parse a KeyStore in PKCS#12 format

Using openssl, it is possible to dump the certificates and private keys from
a PKCS#12 keystore:

    openssl pkcs12 -info -passin pass:changeit -nodes -in store.p12

Nevertheless this command does not show the bags with type "secretBag", that
contain secret keys for symmetric encryption algorithms.

Documentation:

* https://tools.ietf.org/html/rfc7292
  RFC 7292, PKCS #12: Personal Information Exchange Syntax v1.1
* https://tools.ietf.org/html/rfc2315
  RFC 2315, PKCS #7: Cryptographic Message Syntax Version 1.5
* https://tools.ietf.org/html/rfc5208
  RFC 5208, Public-Key Cryptography Standards (PKCS) #8:
  Private-Key Information Syntax Specification Version 1.2
* https://www.openssl.org/docs/man1.0.2/man1/pkcs12.html
  openssl-pkcs12 man page

NB. PKCS#12 pbeWithSHA1And40BitRC2-CBC key-derivation and encryption algorithm
is used to encrypt WebLogic passwords. The code uses JSAFE with algorithm
"PBE/SHA1/RC2/CBC/PKCS12PBE-5-128", which is pbeWithSHA1And40BitRC2-CBC with
five rounds. More information is available on:
* https://bitbucket.org/vladimir_dyuzhev/recover-weblogic-password/src/b48ef4a82db57f12e52788fe08b80e54e847d42c/src/weblogic/security/internal/encryption/JSafeSecretKeyEncryptor.java
* https://www.cryptsoft.com/pkcs11doc/v220/group__SEC__12__27__PKCS____12__PASSWORD__BASED__ENCRYPTION__AUTHENTICATION__MECHANISMS.html
* https://github.com/maaaaz/weblogicpassworddecryptor
* https://blog.netspi.com/decrypting-weblogic-passwords/
* https://github.com/NetSPI/WebLogicPasswordDecryptor/blob/master/Invoke-WebLogicPasswordDecryptor.psm1
"""
import argparse
import binascii
import datetime
import hashlib
import hmac
import logging
import os.path
import re
import struct
import sys
import tempfile

import Cryptodome.Cipher.AES
import Cryptodome.Cipher.ARC2
import Cryptodome.Cipher.DES3

import rc2
import util_asn1
from util_bin import run_openssl_show_cert, run_process_with_input, xx
from util_crypto import report_if_missing_cryptography, describe_der_certificate


logger = logging.getLogger(__name__)


def generate_p12_keystore(password):
    """Generate a PKCS#12 keystore with some content"""
    temporary_dir = tempfile.mkdtemp(suffix='_java_keystore-test')
    ks_path = os.path.join(temporary_dir, 'store.jks')
    try:
        # By default it generates a DSA keypair
        run_process_with_input(
            [
                'keytool', '-genkeypair', '-noprompt',
                '-keyalg', 'dsa',
                '-storetype', 'pkcs12',
                '-keystore', ks_path,
                '-storepass', password,
                '-alias', 'mykeypair',
                '-dname', 'CN=example',
            ],
            None, fatal=True)
        run_process_with_input(
            [
                'keytool', '-genkeypair', '-noprompt',
                '-keyalg', 'rsa', '-sigalg', 'SHA256withRSA',
                '-storetype', 'pkcs12',
                '-keystore', ks_path,
                '-storepass', password,
                '-alias', 'mykeypair_rsa_sha256sig',
                '-dname', 'CN=example',
            ],
            None, fatal=True)

        # Add a secret key
        run_process_with_input(
            [
                'keytool', '-genseckey',
                '-keyalg', 'aes', '-keysize', '192',
                '-storetype', 'pkcs12',
                '-keystore', ks_path,
                '-storepass', password,
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


def pkcs12_derivation(alg, id_byte, password, salt, iterations, result_size=None):
    """Compute a key and iv from a password and salt according to PKCS#12

    id_byte is, according to https://tools.ietf.org/html/rfc7292#appendix-B.3 :
    * 1 to generate a key
    * 2 to generate an initial value (IV)
    * 3 to generate an integrity key

    OpenSSL implementation:
    https://github.com/openssl/openssl/blob/OpenSSL_1_1_1/crypto/pkcs12/p12_key.c
    """
    if alg == 'SHA1':
        hash_func = hashlib.sha1
        u = 160  # SHA1 digest size, in bits
        v = 512  # SHA1 block size, in bits
    elif alg == 'SHA256':
        hash_func = hashlib.sha256
        u = 256  # SHA256 digest size, in bits
        v = 512  # SHA256 block size, in bits
    else:
        raise NotImplementedError("Unimplemented algorithm {} for PKCS#12 key derivation".format(alg))

    assert (u % 8) == (v % 8) == 0
    u_bytes = u // 8
    v_bytes = v // 8

    if result_size is None:
        result_size = u_bytes

    diversifier = struct.pack('B', id_byte) * v_bytes

    expanded_salt_size = v_bytes * ((len(salt) + v_bytes - 1) // v_bytes)
    expanded_salt = (salt * ((expanded_salt_size // len(salt)) + 1))[:expanded_salt_size]
    assert len(expanded_salt) == expanded_salt_size

    pass_bytes = password.encode('utf-16be') + b'\0\0'
    expanded_pass_size = v_bytes * ((len(pass_bytes) + v_bytes - 1) // v_bytes)
    expanded_pass = (pass_bytes * ((expanded_pass_size // len(pass_bytes)) + 1))[:expanded_pass_size]
    assert len(expanded_pass) == expanded_pass_size

    i_size = expanded_salt_size + expanded_pass_size
    i_value = expanded_salt + expanded_pass
    result = b''
    while len(result) < result_size:
        ctx = hash_func(diversifier)
        ctx.update(i_value)
        a_value = ctx.digest()
        for _ in range(1, iterations):
            a_value = hash_func(a_value).digest()
        assert len(a_value) == u_bytes
        result += a_value

        b_value = struct.unpack(v_bytes * 'B', (a_value * ((v_bytes + u_bytes - 1) // u_bytes))[:v_bytes])
        new_i_value = []
        for j in range(0, i_size, v_bytes):
            # Ij = Ij + B + 1
            ij = list(struct.unpack(v_bytes * 'B', i_value[j:j + v_bytes]))
            c = 1
            for k in range(v_bytes - 1, -1, -1):
                c += ij[k] + b_value[k]
                ij[k] = c & 0xff
                c = c >> 8
            new_i_value.append(struct.pack(v_bytes * 'B', *ij))
        i_value = b''.join(new_i_value)
    return result[:result_size]


# Check the implementation with values from "openssl pkcs12" with OPENSSL_DEBUG_KEYGEN
assert pkcs12_derivation(
    'SHA1', 3, 'changeit',
    binascii.unhexlify('c6b068958d7d6085ba52c9cc3212a8fc2e50b3da'), 100000
    ) == binascii.unhexlify('ef3c7f41e19e7bc7bf06650164aff556d15206d7')
assert pkcs12_derivation(
    'SHA1', 1, 'changeit',
    binascii.unhexlify('a9fb3e857865d5e2aeff3983389c980d5de4bf39'), 50000, 24
    ) == binascii.unhexlify('12fe77bc0be3ae0d063c4858e948ff4e85c39daa08b833c9')
assert pkcs12_derivation(
    'SHA1', 2, 'changeit',
    binascii.unhexlify('a9fb3e857865d5e2aeff3983389c980d5de4bf39'), 50000, 8
    ) == binascii.unhexlify('13515c2efce50ef9')
assert pkcs12_derivation(
    'SHA256', 3, 'changeit',
    binascii.unhexlify('ad18630f2594018bd53c4573a7b03f89afda3e87'), 10000
    ) == binascii.unhexlify('894a3be59b92531f08a458c54e4d89493fd9dda40d65b1831ff3ca69f4ff716c')


def try_pkcs12_decrypt(encrypted, enc_alg, password, indent=''):
    """Try to decrypt some data with the given password and PKCS#12 password-based encryption algorithms"""
    if isinstance(enc_alg, util_asn1.PKCS12PbeAlg):
        if enc_alg.oid_name == 'pbeWithSHA1And3-KeyTripleDES-CBC':
            # 192-bits 3DES key and 64-bit IV from SHA1
            key = pkcs12_derivation(alg='SHA1', id_byte=1, password=password, salt=enc_alg.salt,
                                    iterations=enc_alg.iterations, result_size=24)
            iv = pkcs12_derivation(alg='SHA1', id_byte=2, password=password, salt=enc_alg.salt,
                                   iterations=enc_alg.iterations, result_size=8)
            crypto_3des = Cryptodome.Cipher.DES3.new(key, Cryptodome.Cipher.DES3.MODE_CBC, iv)
            decrypted = crypto_3des.decrypt(encrypted)

        elif enc_alg.oid_name == 'pbeWithSHA1And40BitRC2-CBC':
            # 40-bits RC2 key and 64-bit IV from SHA1
            key = pkcs12_derivation(alg='SHA1', id_byte=1, password=password, salt=enc_alg.salt,
                                    iterations=enc_alg.iterations, result_size=5)
            iv = pkcs12_derivation(alg='SHA1', id_byte=2, password=password, salt=enc_alg.salt,
                                   iterations=enc_alg.iterations, result_size=8)
            try:
                crypto_rc2 = Cryptodome.Cipher.ARC2.new(key, Cryptodome.Cipher.ARC2.MODE_CBC, iv, effective_keylen=40)
                decrypted = crypto_rc2.decrypt(encrypted)
            except ValueError:
                # Use custom RC2 implementation because "effective_keylen=40" is not always supported
                # https://github.com/Legrandin/pycryptodome/issues/267
                crypto_rc2 = rc2.RC2(key)
                decrypted = crypto_rc2.decrypt(encrypted, rc2.MODE_CBC, iv)
        else:
            raise NotImplementedError("Unimplemented encryption algorithm {}".format(enc_alg))

    elif isinstance(enc_alg, util_asn1.PKCS12Pbes2Alg):
        pwd_bytes = password.encode('utf-8')
        key = hashlib.pbkdf2_hmac(enc_alg.prf_alg, pwd_bytes, enc_alg.salt, enc_alg.iterations, enc_alg.dklen)
        if enc_alg.enc_alg == 'aes256-CBC-PAD':
            crypto_aes = Cryptodome.Cipher.AES.new(key, Cryptodome.Cipher.AES.MODE_CBC, enc_alg.enc_iv)
            decrypted = crypto_aes.decrypt(encrypted)
        else:
            raise NotImplementedError("Unimplemented encryption algorithm {}".format(enc_alg))

    else:
        raise NotImplementedError("Unimplemented encryption algorithm {}".format(enc_alg))

    # Check PKCS#5 padding
    padlen, = struct.unpack('B', decrypted[-1:])
    if not (1 <= padlen <= 0x10) or any(x != decrypted[-1] for x in decrypted[-padlen:]):
        print("{}* wrong password (bad PKCS#5 padding)".format(indent))
        return None
    print("{}(password: {})".format(indent, repr(password)))
    return decrypted[:-padlen]


def print_p12_keybag(keybag_der, password, show_pem=False, list_only=False, indent=''):
    """Parse PKCS#12 keyBag ASN.1 data"""
    # KeyBag ::= PrivateKeyInfo -- from PKCS #8
    # EncryptedPrivateKeyInfo ::= SEQUENCE {
    #     encryptionAlgorithm  EncryptionAlgorithmIdentifier,
    #     encryptedData        EncryptedData
    # }
    # EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
    # EncryptedData ::= OCTET STRING
    enc_alg_der, enc_data_der = util_asn1.decode_sequence(keybag_der, 2)
    enc_alg = util_asn1.decode_x509_algid(enc_alg_der)
    enc_data = util_asn1.decode_octet_string(enc_data_der)
    print("{}* encryption algorithm: {}".format(indent, enc_alg))
    decrypted = try_pkcs12_decrypt(enc_data, enc_alg, password, indent=indent)
    if decrypted is not None:
        # Show the private key
        util_asn1.show_pkcs8_private_key_info(decrypted, list_only=list_only, show_pem=show_pem, indent=indent)


def print_p12_certBag(certbag_der, show_pem=False, list_only=False, indent=''):
    """Parse PKCS#12 certBag ASN.1 data"""
    # CertBag ::= SEQUENCE {
    #     certId      BAG-TYPE.&id   ({CertTypes}),
    #     certValue   [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId})
    # }
    cert_id_der, cert_value_der = util_asn1.decode_sequence(certbag_der, 2)
    cert_id = util_asn1.decode_oid(cert_id_der)
    cert_value_der = util_asn1.decode_object(cert_value_der)
    if cert_id != 'x509Certificate':
        raise NotImplementedError("Unknown certificate format {}".format(repr(cert_id)))
    cert = util_asn1.decode_octet_string(cert_value_der)

    description = describe_der_certificate(cert)
    if description:
        print("{}* Certificate: {}".format(indent, description))
    else:
        print("{}* Certificate: (no description available)".format(indent))
    run_openssl_show_cert(cert, list_only=list_only, show_pem=show_pem, indent=indent)


def print_p12_secretBag(secretbag_der, password, show_pem=False, list_only=False, indent=''):
    """Parse PKCS#12 secretBag ASN.1 data"""
    # SecretBag ::= SEQUENCE {
    #     secretTypeId   BAG-TYPE.&id ({SecretTypes}),
    #     secretValue    [0] EXPLICIT BAG-TYPE.&Type ({SecretTypes} {@secretTypeId})
    # }
    secret_type_id_der, secret_value_der = util_asn1.decode_sequence(secretbag_der, 2)
    secret_type_id = util_asn1.decode_oid(secret_type_id_der)
    secret_value_der = util_asn1.decode_object(secret_value_der)
    print("{}* secret type: {}".format(indent, secret_type_id))
    secret_value = util_asn1.decode_octet_string(secret_value_der)
    if secret_type_id == 'keyBag':
        print_p12_keybag(secret_value, password, show_pem=show_pem, list_only=list_only, indent=indent)
    else:
        raise NotImplementedError("Unimplemented secretBag type {}".format(secret_type_id))


def print_p12_safe_contents(safe_contents_der, password, show_pem=False, list_only=False, indent=''):
    """Parse PKCS#12 SafeContents ASN.1 data

    https://tools.ietf.org/html/rfc7292#section-4.2
        The SafeContents type is made up of SafeBags.  Each SafeBag holds one
        piece of information -- a key, a certificate, etc. -- which is
        identified by an object identifier.
    """
    # SafeContents ::= SEQUENCE OF SafeBag
    # SafeBag ::= SEQUENCE {
    #     bagId          BAG-TYPE.&id ({PKCS12BagSet})
    #     bagValue       [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
    #     bagAttributes  SET OF PKCS12Attribute OPTIONAL
    # }
    # PKCS12Attribute ::= SEQUENCE {
    #     attrId      ATTRIBUTE.&id ({PKCS12AttrSet}),
    #     attrValues  SET OF ATTRIBUTE.&Type ({PKCS12AttrSet}{@attrId})
    # } -- This type is compatible with the X.500 type 'Attribute'
    # PKCS12AttrSet ATTRIBUTE ::= {
    #     friendlyName | -- from PKCS #9
    #     localKeyId,    -- from PKCS #9
    #     ... -- Other attributes are allowed
    # }
    safe_bags = util_asn1.decode_sequence(safe_contents_der)
    print("{}* {} {}:".format(indent, len(safe_bags), "safe bags" if len(safe_bags) >= 2 else "safe bag"))
    for idx_safe_bag, safe_bag_der in enumerate(safe_bags):
        safe_bag = util_asn1.decode_sequence(safe_bag_der, counts=(2, 3))
        bag_id = util_asn1.decode_oid(safe_bag[0])
        bag_value = util_asn1.decode_object(safe_bag[1])
        try:
            bag_attributes = util_asn1.decode_set(safe_bag[2]) if len(safe_bag) >= 3 else []
        except NotImplementedError as exc:
            # Recover from error caused by old PyCrypto
            logger.warning("Unable to decode bag attributes: %s", exc)
            attr_descs = ['?']
        else:
            attr_descs = []
            for bag_attribute_der in bag_attributes:
                attr_id_der, attr_values_der = util_asn1.decode_sequence(bag_attribute_der, 2)
                attr_id = util_asn1.decode_oid(attr_id_der)
                attr_values_der = util_asn1.decode_set(attr_values_der)
                attr_values = [util_asn1.decode_any_string(v) for v in attr_values_der]
                attr_descs.append("{}={}".format(attr_id, ','.join(repr(v) for v in attr_values)))
                if attr_id == 'localKeyID' and len(attr_values) == 1 and isinstance(attr_values[0], str):
                    m = re.match(r'^Time ([0-9]+)$', attr_values[0])
                    if m:
                        # Parse the timestamp from the local key ID
                        timestamp = int(m.group(1))
                        attr_descs.append("date='{}'".format(datetime.datetime.fromtimestamp(timestamp / 1000.)))
        print("{}  [{}] {} ({})".format(indent, idx_safe_bag + 1, bag_id, ', '.join(attr_descs)))

        if bag_id == 'keyBag':
            print_p12_keybag(bag_value, password, show_pem=show_pem, list_only=list_only, indent=indent + "    ")

        elif bag_id == 'certBag':
            print_p12_certBag(bag_value, show_pem=show_pem, list_only=list_only, indent=indent + "    ")

        elif bag_id == 'secretBag':
            print_p12_secretBag(bag_value, password, show_pem=show_pem, list_only=list_only, indent=indent + "    ")

        else:
            print("{}        * bag value: {}".format(indent, repr(bag_value)))
            raise NotImplementedError("Unimplemented bag id {}".format(bag_id))


def print_p12_keystore(ks_content, password, show_pem=False, list_only=False):
    """Parse a PKCS#12 KeyStore file and print it"""
    # run_process_with_input(['openssl', 'asn1parse', '-i', '-inform', 'DER'], ks_content, fatal=True)

    # PFX (Personal Information Exchange) is defined as:
    # PFX ::= SEQUENCE {
    #     version     INTEGER {v3(3)}(v3,...),
    #     authSafe    ContentInfo,
    #     macData     MacData OPTIONAL
    # }
    version, authsafe_der, macdata_der = util_asn1.decode_sequence(ks_content, 3)
    if version != 3:
        raise NotImplementedError("Unimplemented PFX version {}".format(version))

    # ContentInfo ::= SEQUENCE {
    #     contentType ContentType,
    #     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
    # }
    # ContentType ::= OBJECT IDENTIFIER
    authsafe_content_type_der, authsafe_content_der = util_asn1.decode_sequence(authsafe_der, 2)
    authsafe_content_type = util_asn1.decode_oid(authsafe_content_type_der)
    if authsafe_content_type != 'pkcs7-data':
        raise NotImplementedError("Unimplemented PFX content type {}".format(authsafe_content_type))
    authsafe_content_der = util_asn1.decode_object(authsafe_content_der)
    authsafe_content = util_asn1.decode_octet_string(authsafe_content_der)

    # MacData ::= SEQUENCE {
    #     mac         DigestInfo,
    #     macSalt     OCTET STRING,
    #     iterations  INTEGER DEFAULT 1
    # }
    macdata_asn1 = util_asn1.decode_sequence(macdata_der)
    if len(macdata_asn1) == 2:
        mac_der, mac_salt_der = macdata_asn1
        mac_iterations = 1
    elif len(macdata_asn1) == 3:
        mac_der, mac_salt_der, mac_iterations = macdata_asn1
    else:
        raise ValueError("Unexpected number of items in ASN.1 MacData sequence")
    mac_salt = util_asn1.decode_octet_string(mac_salt_der)

    # DigestInfo ::= SEQUENCE {
    #     digestAlgorithm DigestAlgorithmIdentifier,
    #     digest Digest
    # }
    # DigestAlgorithmIdentifier ::= AlgorithmIdentifier
    # Digest ::= OCTET STRING
    mac_digest_algorithm_der, mac_digest_der = util_asn1.decode_sequence(mac_der, 2)
    mac_digest_algorithm = util_asn1.decode_x509_algid(mac_digest_algorithm_der)
    mac_digest = util_asn1.decode_octet_string(mac_digest_der)

    print("* PKCS#12 Keystore MAC:")
    print("    * algorithm: {}".format(mac_digest_algorithm))
    print("    * salt: {}".format(xx(mac_salt)))
    print("    * iterations: {}".format(mac_iterations))
    print("    * HMAC digest: {}".format(xx(mac_digest)))

    mac_key = pkcs12_derivation(
        alg=mac_digest_algorithm,
        id_byte=3,
        password=password,
        salt=mac_salt,
        iterations=mac_iterations)

    if mac_digest_algorithm == 'SHA1':
        hash_func = hashlib.sha1
    elif mac_digest_algorithm == 'SHA256':
        hash_func = hashlib.sha256
    else:
        raise NotImplementedError("Unimplemented algorithm {} for PKCS#12 hmac verification".format(
            mac_digest_algorithm))

    mac_hmac = hmac.new(key=mac_key, msg=authsafe_content, digestmod=hash_func).digest()
    if mac_hmac == mac_digest:
        print("    (password: {})".format(repr(password)))
        print("    (HMAC key: {})".format(xx(mac_key)))
    else:
        print("    (computed HMAC: {})".format(xx(mac_hmac)))
        print("    * wrong password (pad HMAC digest)")

    # AuthenticatedSafe ::= SEQUENCE OF ContentInfo
    #     -- Data if unencrypted
    #     -- EncryptedData if password-encrypted
    #     -- EnvelopedData if public key-encrypted
    authsafe_seq = util_asn1.decode_sequence(authsafe_content)
    print("* {} data blocks:".format(len(authsafe_seq)))
    for blk_index, blk_der in enumerate(authsafe_seq):
        blk_content_type_der, blk_content_der = util_asn1.decode_sequence(blk_der, 2)
        blk_content_type = util_asn1.decode_oid(blk_content_type_der)
        blk_content_der = util_asn1.decode_object(blk_content_der)  # tag "cont[0]"

        if blk_content_type == 'pkcs7-data':
            safe_contents = util_asn1.decode_octet_string(blk_content_der)
            print("  [{}] unencrypted safe contents:".format(blk_index + 1))
            print_p12_safe_contents(safe_contents, password, show_pem=show_pem, list_only=list_only, indent="    ")
        elif blk_content_type == 'pkcs7-encryptedData':
            print("  [{}] encrypted safe contents:".format(blk_index + 1))
            # EncryptedData ::= SEQUENCE {
            #      version Version,
            #      encryptedContentInfo EncryptedContentInfo
            # }
            encblk_version, encrypted_ci_der = util_asn1.decode_sequence(blk_content_der, 2)
            if encblk_version != 0:
                raise NotImplementedError("Unimplemented PKCS#7 EncryptedData version {}".format(encblk_version))

            # EncryptedContentInfo ::= SEQUENCE {
            #     contentType ContentType,
            #     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
            #     encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
            # }
            # ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
            # EncryptedContent ::= OCTET STRING
            enc_ctype_der, enc_alg_der, enc_content_der = util_asn1.decode_sequence(encrypted_ci_der, 3)
            enc_ctype = util_asn1.decode_oid(enc_ctype_der)
            enc_alg = util_asn1.decode_x509_algid(enc_alg_der)
            enc_content = util_asn1.decode_object(enc_content_der)  # tag "cont[0]"
            if enc_ctype != 'pkcs7-data':
                raise NotImplementedError("Unimplemented PKCS#7 EncryptedData content type {}".format(enc_ctype))
            print("    * encryption algorithm: {}".format(enc_alg))
            safe_contents = try_pkcs12_decrypt(enc_content, enc_alg, password, indent="    ")
            if safe_contents is not None:
                print_p12_safe_contents(safe_contents, password, show_pem=show_pem, list_only=list_only, indent="    ")
        else:
            raise NotImplementedError("Unimplemented bag content type {}".format(blk_content_type))


def main(argv=None):
    """Program entry point"""
    parser = argparse.ArgumentParser(
        description="Parse a PKCS#12 keystore file",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('input', metavar='KEYSTORE', nargs='?', type=str,
                        help="load a keystore instead of generating one")
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
            ks_content = generate_p12_keystore(args.password)
        except ValueError as exc:
            logger.fatal("Generating a keystore failed: %s", exc)
            return 1
        logger.debug("Parsing keystore (%d bytes)", len(ks_content))

    try:
        print_p12_keystore(ks_content, args.password, show_pem=args.pem, list_only=args.list)
    except ValueError as exc:
        logger.fatal("Parsing the keystore failed: %s", exc)
        raise  # Show the stack trace

    return 0


if __name__ == '__main__':
    sys.exit(main())
