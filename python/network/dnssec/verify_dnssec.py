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
"""Verify the DNSSEC signatures of a domain"""
import argparse
import base64
import binascii
import copy
import datetime
import logging
import os
import os.path
import re
import socket
import ssl
import struct
import sys

import Cryptodome.PublicKey.RSA
import Cryptodome.Hash.SHA
import Cryptodome.Hash.SHA256
import Cryptodome.Hash.SHA512
import Cryptodome.Signature.PKCS1_v1_5
import Cryptodome.Util.number

if sys.version_info >= (3,):
    import urllib.request
else:
    import urllib2

try:
    import dns.resolver
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

# PyCryptodome provides ECDSA but not PyCrypto
try:
    import Cryptodome.PublicKey.ECC
    import Cryptodome.Signature.DSS
    HAVE_CRYPTO_ECDSA = True
except ImportError:
    HAVE_CRYPTO_ECDSA = False


TLD_REPORT_URL = 'https://stats.research.icann.org/dns/tld_report/'
TLD_OPENPROVIDER_URL = 'https://support.openprovider.eu/hc/en-us/articles/216648838-List-of-TLDs-that-support-DNSSEC'
TLD_LIST_PATH = os.path.join(os.path.dirname(__file__), 'tld.list.txt')
MOST_USED_TLD_LIST_PATH = os.path.join(os.path.dirname(__file__), 'most_used_tld.list.txt')
DNS_CACHE_PATH = os.path.join(os.path.dirname(__file__), 'dns_cache')


logger = logging.getLogger(__name__)


def load_tld_list(filename):
    """Load a list of Top Level Domains"""
    with open(filename, 'r') as ftld:
        # Drop comments in the file
        lines = [l.split('#', 1)[0].strip() for l in ftld.readlines()]
    tlds = [l for l in lines if l]
    # Check the sanity of the format of the TLDs
    assert all(re.match(r'^([a-z0-9-.]+)\.$', tld) for tld in tlds)
    return tlds


MOST_USED_TOP_LEVEL_DOMAINS = load_tld_list(MOST_USED_TLD_LIST_PATH)


def update_tld_list_from_icann():
    """Update the TLD list from stats.research.icann.org.

    Since 2022-06-23 it has been broken
    https://stats.research.icann.org/dns/tld_report/archive/20220623.000101.html
    """
    # The certificate declares *.icann.org, which does not match stats.research.icann.org
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    if sys.version_info >= (3,):
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        req = urllib.request.Request(TLD_REPORT_URL)
    else:
        opener = urllib2.build_opener(urllib2.HTTPSHandler(context=ctx))
        req = urllib2.Request(TLD_REPORT_URL)
    tlds = {}
    with opener.open(req) as resp:
        for line in resp:
            line = line.decode('utf-8', 'replace')
            # Match for example:
            #    '<tr bgcolor=#00CC00><td align=left><a href=
            #    http://www.iana.org/domains/root/db/org.html>org.</a></td><td
            #    align=left>YES</td><td align=left>YES</td><td>NO</td></tr>\n'
            m = re.match(r'^<tr[^>]*><td[^>]*><a[^>]*>([^<]+)</a></td><td[^>]*>([^<]+)</td>', line)
            if m:
                tld_desc, text_is_signed = m.groups()
                # Replace &nbsp; with a comment
                tld_desc = re.sub(r'(&nbsp;)+', ' # ', tld_desc)
                if not re.match(r'^([a-z0-9-]+)\.( # .*)?$', tld_desc):
                    print("Ignoring invalid TLD description {}".format(tld_desc))
                    continue
                if text_is_signed not in ('YES', 'NO'):
                    print("Ignoring invalid signed state for TLD {}".format(tld_desc))
                    continue
                if tld_desc in tlds:
                    print("Ignoring duplicate TLD {}".format(tld_desc))
                    continue
                tlds[tld_desc] = (text_is_signed == 'YES')

    # Update the list
    all_tlds = [
        (tld_desc if is_signed else '# {} (not signed)'.format(tld_desc))
        for tld_desc, is_signed in sorted(tlds.items())]
    with open(TLD_LIST_PATH, 'w') as ftld:
        ftld.write('# List from {}\n{}\n'.format(TLD_REPORT_URL, '\n'.join(all_tlds)))


def update_tld_list_from_openprovider():
    """Update the TLD list from support.openprovider.eu."""
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    }
    if sys.version_info >= (3,):
        urlopen = urllib.request.urlopen
        req = urllib.request.Request(TLD_OPENPROVIDER_URL, headers=headers)
    else:
        req = urllib2.Request(TLD_OPENPROVIDER_URL, headers=headers)
    tlds = {}
    with urlopen(req) as resp:
        # Read table such as:
        # <tr style="height: 22px;">
        # <td style="width: 203px; height: 22px;" data-sheets-value="{&quot;1&quot;:2,&quot;2&quot;:&quot;fr&quot;}"
        #   >fr</td>
        # <td style="width: 308px; height: 22px;" data-sheets-value="{&quot;1&quot;:2,&quot;2&quot;:&quot;
        #   [6,8,10,12,13]&quot;}">[6,8,10,12,13]</td>
        # </tr>
        current_row = []
        for line in resp:
            line = line.decode('utf-8', 'replace')
            m = re.match(r'^<td[^>]*data-sheets-value="\{([^>"]+)\}"', line)
            if m:
                values = m.group(1).split(":", 2)
                if len(values) != 3:
                    print("Ignoring invalid TLD record {}".format(values))
                    continue
                current_row.append(values[2].replace("&quot;", ""))
            if current_row and '</tr>' in line:
                if len(current_row) != 2:
                    print("Ignoring invalid TLD row {}".format(current_row))
                    current_row = []
                    continue
                tld = current_row[0] + "."
                is_signed = current_row[1] != "NULL"
                current_row = []
                if tld in tlds:
                    print("Ignoring duplicate TLD {}".format(tld))
                    continue
                tlds[tld] = is_signed

    # Update the list
    all_tlds = [
        (tld_desc if is_signed else '# {} (not signed)'.format(tld_desc))
        for tld_desc, is_signed in sorted(tlds.items())]
    with open(TLD_LIST_PATH, 'w') as ftld:
        ftld.write('# List from {}\n{}\n'.format(TLD_OPENPROVIDER_URL, '\n'.join(all_tlds)))


def decode_bigint_be(data):
    """Decode a Big-Endian big integer"""
    return Cryptodome.Util.number.bytes_to_long(data)


DNSSEC_ALGORITHMS = {
    1: 'RSA/MD5',
    3: 'DSA/SHA1',
    5: 'RSA/SHA1',
    6: 'DSA-NSEC3-SHA1',
    7: 'RSA/SHA1-NSEC3-SHA1',
    8: 'RSA/SHA256',
    10: 'RSA/SHA512',
    13: 'ECDSA-P256/SHA256',
    14: 'ECDSA-P384/SHA384',
    15: 'Ed25519',
    16: 'Ed448',
}

DNSSEC_DIGESTS = {
    1: 'SHA1',  # https://tools.ietf.org/html/rfc3658 Delegation Signer (DS) Resource Record (RR)
    2: 'SHA256',  # https://tools.ietf.org/html/rfc4509
                  # Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records (RRs)
}

DNS_RDATA_CLASSES = {
    'IN': 1,
    'ANY': 255,
}

DNS_RDATA_TYPES = {
    'NONE': 0,
    'A': 1,
    'NS': 2,
    'MD': 3,
    'MF': 4,
    'CNAME': 5,
    'SOA': 6,
    'MB': 7,
    'MG': 8,
    'MR': 9,
    'NULL': 10,
    'WKS': 11,
    'PTR': 12,
    'HINFO': 13,
    'MINFO': 14,
    'MX': 15,
    'TXT': 16,
    'RP': 17,
    'AFSDB': 18,
    'X25': 19,
    'ISDN': 20,
    'RT': 21,
    'NSAP': 22,
    'NSAP_PTR': 23,
    'SIG': 24,
    'KEY': 25,
    'PX': 26,
    'GPOS': 27,
    'AAAA': 28,
    'LOC': 29,
    'NXT': 30,
    'SRV': 33,
    'NAPTR': 35,
    'KX': 36,
    'CERT': 37,
    'A6': 38,
    'DNAME': 39,
    'OPT': 41,
    'APL': 42,
    'DS': 43,
    'SSHFP': 44,
    'IPSECKEY': 45,
    'RRSIG': 46,
    'NSEC': 47,
    'DNSKEY': 48,
    'DHCID': 49,
    'NSEC3': 50,
    'NSEC3PARAM': 51,
    'TLSA': 52,
    'HIP': 55,
    'CDS': 59,
    'CDNSKEY': 60,
    'CSYNC': 62,
    'SPF': 99,
    'UNSPEC': 103,
    'EUI48': 108,
    'EUI64': 109,
    'TKEY': 249,
    'TSIG': 250,
    'IXFR': 251,
    'AXFR': 252,
    'MAILB': 253,
    'MAILA': 254,
    'ANY': 255,
    'URI': 256,
    'CAA': 257,
    'AVC': 258,
    'TA': 32768,
    'DLV': 32769,
}


def dns_name_to_wire(domain_name, origin=None):
    """Transform a domain name to wire-format"""
    if not domain_name.endswith('.'):
        assert origin is not None
        assert origin.endswith('.')
        domain_name += '.' + origin.lstrip('.')
    if domain_name == '.':
        return b'\0'
    labels = domain_name.encode('ascii').lower().split(b'.')
    return b''.join(struct.pack('B', len(x)) + x for x in labels)


class DNSKeyRecord(object):
    """Content of a DNSKEY record:
    * Flags
    * Protocol: always 3
    * Algorithm: https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xml
    * Public key: base64-encoded
    """
    def __init__(self, text_content):
        flags, protocol, algorithm, pubkey = text_content.split(None, 3)
        assert protocol == '3', "unknown protocol {}".format(repr(protocol))
        self.flags = int(flags)
        self.algorithm = int(algorithm)
        self.protocol = int(protocol)
        self.alg_desc = DNSSEC_ALGORITHMS.get(self.algorithm, 'Unknown ({})'.format(self.algorithm))
        self.pubkey = base64.b64decode(pubkey.replace(' ', ''))
        self.key_tag = self.get_key_tag()
        self.signer_returns_bool = True
        if self.algorithm == 5:
            # RSA/SHA1
            exponent_size = struct.unpack('B', self.pubkey[:1])[0]
            assert 1 + exponent_size < len(self.pubkey)
            exponent = decode_bigint_be(self.pubkey[1:1 + exponent_size])
            modulus = decode_bigint_be(self.pubkey[1 + exponent_size:])
            self.alg_desc += '(RSA{})'.format(modulus.bit_length())
            pubkey = Cryptodome.PublicKey.RSA.construct((modulus, exponent))
            self.signer = Cryptodome.Signature.PKCS1_v1_5.new(pubkey)
            self.hash = Cryptodome.Hash.SHA
        elif self.algorithm == 7:
            # RSA/SHA1-NSEC3-SHA1
            exponent_size = struct.unpack('B', self.pubkey[:1])[0]
            assert 1 + exponent_size < len(self.pubkey)
            exponent = decode_bigint_be(self.pubkey[1:1 + exponent_size])
            modulus = decode_bigint_be(self.pubkey[1 + exponent_size:])
            self.alg_desc += '(RSA{})'.format(modulus.bit_length())
            pubkey = Cryptodome.PublicKey.RSA.construct((modulus, exponent))
            self.signer = Cryptodome.Signature.PKCS1_v1_5.new(pubkey)
            self.hash = Cryptodome.Hash.SHA
        elif self.algorithm == 8:
            # RSA/SHA256
            exponent_size = struct.unpack('B', self.pubkey[:1])[0]
            assert 1 + exponent_size < len(self.pubkey)
            exponent = decode_bigint_be(self.pubkey[1:1 + exponent_size])
            modulus = decode_bigint_be(self.pubkey[1 + exponent_size:])
            self.alg_desc += '(RSA{})'.format(modulus.bit_length())
            pubkey = Cryptodome.PublicKey.RSA.construct((modulus, exponent))
            self.signer = Cryptodome.Signature.PKCS1_v1_5.new(pubkey)
            self.hash = Cryptodome.Hash.SHA256
        elif self.algorithm == 10:
            # RSA/SHA512
            exponent_size = struct.unpack('B', self.pubkey[:1])[0]
            assert 1 + exponent_size < len(self.pubkey)
            exponent = decode_bigint_be(self.pubkey[1:1 + exponent_size])
            modulus = decode_bigint_be(self.pubkey[1 + exponent_size:])
            self.alg_desc += '(RSA{})'.format(modulus.bit_length())
            pubkey = Cryptodome.PublicKey.RSA.construct((modulus, exponent))
            self.signer = Cryptodome.Signature.PKCS1_v1_5.new(pubkey)
            self.hash = Cryptodome.Hash.SHA512
        elif self.algorithm == 13:
            # ECDSA-P256/SHA256
            assert len(self.pubkey) == 64
            pt_x = decode_bigint_be(self.pubkey[:32])
            pt_y = decode_bigint_be(self.pubkey[32:])
            if HAVE_CRYPTO_ECDSA:
                pubkey = Cryptodome.PublicKey.ECC.construct(curve='prime256v1', point_x=pt_x, point_y=pt_y)
                self.signer = Cryptodome.Signature.DSS.new(pubkey, 'fips-186-3')
            else:
                # A warning message was reported in main()
                logger.debug("Ignoring ECDSA verification")
                self.signer = None
            self.hash = Cryptodome.Hash.SHA256
            self.signer_returns_bool = False
        else:
            raise ValueError("Unimplemented DNSKEY algorithm %d (%s)" % (self.algorithm, self.alg_desc))

    def to_wire(self):
        """Produce the wire format of the DNSKEY record

        https://tools.ietf.org/html/rfc4034#section-2.1
        """
        return struct.pack('>HBB', self.flags, self.protocol, self.algorithm) + self.pubkey

    def get_key_tag(self):
        """Compute the DNSKEY keytag"""
        if self.algorithm == 1:
            # RSA/MD5 keytag
            return struct.unpack('>H', self.pubkey[-3:-1])[0]
        wire = self.to_wire()
        if len(wire) % 2:
            wire += b'\0'
        tag = 0
        for pos in range(0, len(wire), 2):
            tag = (tag + struct.unpack('>H', wire[pos:pos + 2])[0]) & 0xffffffff
        return (tag + (tag >> 16)) & 0xffff

    def verify(self, signed_data, signature):
        """Verify a signature"""
        hashobj = self.hash.new(signed_data)
        if self.signer is None:
            # Ignore vetification if ECDSA is not implemented in Crypto
            return True
        if not self.signer_returns_bool:
            # The verification raises an exception if it fails
            try:
                self.signer.verify(hashobj, signature)
                return True
            except ValueError:
                return False
        # PKCS#1 v1.5 verification returns a boolean
        return self.signer.verify(hashobj, signature)

    def __repr__(self):
        flags_desc = []
        if self.flags & 0x100:
            flags_desc.append('Zone Key')  # Zone-signing key
        if self.flags & 1:
            flags_desc.append('Secure Entry Point')  # Key-signing key
        return '<{}(flags={:#x}{}, alg={}, keytag={})>'.format(
            self.__class__.__name__,
            self.flags,
            ' ({})'.format(', '.join(flags_desc)) if flags_desc else '',
            self.alg_desc,
            self.key_tag)


class DSRecord(object):
    """Content of a DS (Delegation Signer) record:
    * key tag
    * algorithm
    * digest type
    * digest
    """
    def __init__(self, text_content):
        key_tag, algorithm, digest_type, digest = text_content.split(None, 3)
        self.key_tag = int(key_tag)
        self.algorithm = int(algorithm)
        self.digest_type = int(digest_type)
        self.digest = binascii.unhexlify(digest.replace(' ', ''))
        self.alg_desc = DNSSEC_ALGORITHMS.get(self.algorithm, 'Unknown ({})'.format(self.algorithm))
        self.digest_desc = DNSSEC_DIGESTS.get(self.digest_type, 'Unknown ({})'.format(self.digest_type))
        if self.digest_type == 1:
            self.hash = Cryptodome.Hash.SHA
        elif self.digest_type == 2:
            self.hash = Cryptodome.Hash.SHA256
        else:
            self.hash = None

    def to_wire(self):
        """Produce the wire format of the DS record

        https://tools.ietf.org/html/rfc3658#section-2.4
        """
        return struct.pack('>HBB', self.key_tag, self.algorithm, self.digest_type) + self.digest

    def __repr__(self):
        return '<{}(keytag={}, alg={}, digest={}>'.format(
            self.__class__.__name__,
            self.key_tag, self.alg_desc, self.digest_desc)

    def verify_key(self, domain, dnskey):
        """Verify that the given DNS key matches the digest"""
        if dnskey.key_tag != self.key_tag:
            raise ValueError("DS record verification error: key tag mismatch ({} != {})".format(
                dnskey.key_tag, self.key_tag))
        if dnskey.algorithm != self.algorithm:
            raise ValueError("DS record verification error: algorithm mismatch ({} != {})".format(
                dnskey.alg_desc, self.alg_desc))
        encoded_fqdn = dns_name_to_wire(domain, origin='.')
        digest = self.hash.new(encoded_fqdn + dnskey.to_wire()).digest()
        if digest != self.digest:
            raise ValueError("DS record verification error: wrong digest")
        return True


class RRSigRecord(object):
    """Content of a RRSIG (RRset Signature) record:
    * Type Covered
    * Algorithm
    * Labels
    * Original TTL
    * Signature Expiration
    * Signature Inception
    * Key Tag
    * Signer's Name
    * Signature
    """
    def __init__(self, rdtype, text_content):
        algorithm, labels, ottl, sigexp, siginc, keytag, signer, signature = text_content.split(None, 7)
        self.rdtype = rdtype
        self.algorithm = int(algorithm)
        self.alg_desc = DNSSEC_ALGORITHMS.get(self.algorithm, 'Unknown ({})'.format(self.algorithm))
        self.labels = int(labels)
        self.orig_ttl = int(ottl)
        self.epoch = datetime.datetime.strptime('19700101000000', '%Y%m%d%H%M%S')
        self.sig_expiration = datetime.datetime.strptime(sigexp, '%Y%m%d%H%M%S')
        self.sig_inception = datetime.datetime.strptime(siginc, '%Y%m%d%H%M%S')
        self.keytag = int(keytag)
        self.signer = signer
        self.signature = base64.b64decode(signature.replace(' ', ''))

    def __repr__(self):
        return '<{}(alg={}, signer={}, keytag={}, siglen={} bits, dates=({}, {})>'.format(
            self.__class__.__name__,
            self.alg_desc, repr(self.signer), self.keytag, len(self.signature) * 8,
            self.sig_inception.strftime('"%Y-%m-%d %H:%M:%S"').replace(' 00:00:00', ''),
            self.sig_expiration.strftime('"%Y-%m-%d %H:%M:%S"').replace(' 00:00:00', ''))

    def to_wire_without_signature(self):
        """Produce the wire format of the RRSIG record, without the signature

        https://tools.ietf.org/html/rfc4034#section-3.1
        """
        return struct.pack(
            '>HBBIIIH',
            DNS_RDATA_TYPES[self.rdtype],
            self.algorithm,
            self.labels,
            self.orig_ttl,
            int((self.sig_expiration - self.epoch).total_seconds()),
            int((self.sig_inception - self.epoch).total_seconds()),
            self.keytag,
        ) + dns_name_to_wire(self.signer)


class NSRecord(object):
    """Content of a NS (NameServer) record"""
    def __init__(self, text_content):
        self.name_server = text_content

    def to_wire(self):
        """Produce the wire format of the NS record"""
        return dns_name_to_wire(self.name_server)

    def __repr__(self):
        return '<{}({})>'.format(self.__class__.__name__, self.name_server)


class ARecord(object):
    """Content of a A (IPv4 address) record"""
    def __init__(self, text_content):
        self.address = text_content

    def to_wire(self):
        """Produce the wire format of the A record"""
        return socket.inet_pton(socket.AF_INET, self.address)

    def __repr__(self):
        return '<{}({})>'.format(self.__class__.__name__, self.address)


class AAAARecord(object):
    """Content of a AAAA (IPv6 address) record"""
    def __init__(self, text_content):
        self.address = text_content

    def to_wire(self):
        """Produce the wire format of the AAAA record"""
        return socket.inet_pton(socket.AF_INET6, self.address)

    def __repr__(self):
        return '<{}({})>'.format(self.__class__.__name__, self.address)


class DNSCache(object):
    """Handle a cache of DNS results in text files"""
    def __init__(self, cache_dir, use_cloudflare=False, use_google=False):
        self.cache_dir = cache_dir
        self.use_cloudflare = use_cloudflare
        self.use_google = use_google
        # Split records whose signatures have been verified from the other ones
        self.unverified_cache = {}
        self.verified_cache = {}
        self.refreshed_records = set()
        self.load()

    def load(self):
        """Load the DNS cache"""
        if not os.path.exists(self.cache_dir):
            return
        self.unverified_cache = {}
        for filename in os.listdir(self.cache_dir):
            if filename.endswith('_cache.txt'):
                with open(os.path.join(self.cache_dir, filename), 'r') as fd:
                    for line in fd:
                        self.load_dns_line(line.strip())
        # Assume the cache has previously been verified
        # This allows this program to be run offline
        self.verified_cache = copy.deepcopy(self.unverified_cache)
        # Try migrating known signed domain too (using cached RRSIG records)
        self.verify_all_cached_records()
        # Clean up the cache of unverified records
        self.unverified_cache = {}

    def load_dns_line(self, line):
        """Load a DNS record into the cache, from a text line"""
        domain, rdclass, rdtype, content = line.split(None, 3)
        if rdtype == 'RRSIG':
            # RRSIG is paramtrized by another record type
            rdtype2, content = content.split(None, 1)
            rdtype += ' ' + rdtype2
        self.load_dns_record(domain.lower(), rdclass, rdtype, content.strip())

    def load_dns_record(self, domain, rdclass, rdtype, content):
        """Load a DNS record into the cache"""
        # Sanity checks
        assert re.match(r'^([a-z0-9-.]*)\.$', domain)
        assert rdclass == 'IN', "unknown rdclass {}".format(repr(rdclass))
        base_rdtype = rdtype[6:] if rdtype.startswith('RRSIG ') else rdtype
        assert base_rdtype in DNS_RDATA_TYPES, "unknown rdtype {}".format(repr(rdtype))
        assert content

        if domain not in self.unverified_cache:
            self.unverified_cache[domain] = {}
        if rdclass not in self.unverified_cache[domain]:
            self.unverified_cache[domain][rdclass] = {}
        if rdtype not in self.unverified_cache[domain][rdclass]:
            self.unverified_cache[domain][rdclass][rdtype] = []
        self.unverified_cache[domain][rdclass][rdtype].append(content)

    def save(self):
        """Save the cache, removing all previous files and regenerating them"""
        # Split the cache dict by domain
        cache_by_file = {}
        for domain, domain_cache in self.verified_cache.items():
            # Split RRSIG records into a separate file
            rrsig_file = '{}RRSIG'.format(domain)
            cache_by_file[domain] = set()
            cache_by_file[rrsig_file] = set()
            for rdclass, rdclass_content in domain_cache.items():
                for rdtype, rdtype_content in rdclass_content.items():
                    filename = rrsig_file if rdtype.startswith('RRSIG ') else domain
                    for content in rdtype_content:
                        cache_by_file[filename].add(
                            '{} {} {} {}\n'.format(domain, rdclass, rdtype, content))

        # Remove previous cache
        if os.path.exists(self.cache_dir):
            for filename in os.listdir(self.cache_dir):
                if filename.endswith('_cache.txt'):
                    os.remove(os.path.join(self.cache_dir, filename))
        else:
            os.makedirs(self.cache_dir)

        # Generate a new one
        for domain, lines in sorted(cache_by_file.items()):
            with open(os.path.join(self.cache_dir, 'DNS_{}_cache.txt'.format(domain)), 'w') as fout:
                fout.write(''.join(sorted(lines)))

    def _refresh_dns_records_online(self, domain, rdtype_text):
        """Get the DNS records for the specified (domain, type), from online DNS servers"""
        resolver = dns.resolver.Resolver()
        resolver.use_edns(0, dns.flags.DO, 4096)
        nameservers = []
        if self.use_cloudflare:
            # https://cloudflare-dns.com/dns/
            nameservers += ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]
        if self.use_google:
            # https://developers.google.com/speed/public-dns/docs/using#addresses
            nameservers += ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"]
        if nameservers:
            resolver.nameservers = nameservers
        rdtype = dns.rdatatype.from_text(rdtype_text)
        rdclass = dns.rdataclass.IN

        try:
            response = resolver.query(domain, rdtype, rdclass, True).response
        except dns.resolver.NoAnswer:
            response = None
        except dns.resolver.NXDOMAIN:
            response = None

        # Remove old entries from the caches
        if domain in self.verified_cache and 'IN' in self.verified_cache[domain]:
            rrsig_type_text = 'RRSIG ' + rdtype_text
            if rdtype_text in self.verified_cache[domain]['IN']:
                del self.verified_cache[domain]['IN'][rdtype_text]
            if rrsig_type_text in self.verified_cache[domain]['IN']:
                del self.verified_cache[domain]['IN'][rrsig_type_text]

        # Update the cache
        if response is None:
            logger.debug("DNS request to %s %r: no answer", rdtype_text, domain)
            return

        logger.debug("DNS request to %s %r: %d %s", rdtype_text, domain,
                     len(response.answer),
                     'answers' if len(response.answer) >= 2 else 'answer')
        for answer in response.answer:
            for line in answer.to_text().splitlines():
                # Strip the TTL (Time to Live) from the result
                domain, _, remaining = line.split(None, 2)
                self.load_dns_line('{} {}'.format(domain, remaining))

        # Verify the new record before trying to verify other things
        self.verify_cached_record(domain, 'IN', rdtype_text, refresh=True)

    def verify_cached_record(self, domain, rdclass, rdtype, refresh=False, do_not_remove=False):
        """Verify a record in the unverified cache"""
        if rdtype.startswith('RRSIG '):
            signed_rdtype = rdtype[6:]
        else:
            signed_rdtype = rdtype
            rdtype = 'RRSIG ' + rdtype
        try:
            rdtype_content = self.unverified_cache[domain][rdclass][rdtype]
        except KeyError:
            return None

        if signed_rdtype not in self.unverified_cache[domain][rdclass]:
            logger.warning("found %r without %r for domain %r in unverified cache",
                           rdtype, signed_rdtype, domain)
            return None

        # Convert signed records to classes
        record_classes = {
            'DNSKEY': DNSKeyRecord,
            'DS': DSRecord,
            'NS': NSRecord,
            'A': ARecord,
            'AAAA': AAAARecord,
        }
        record_class = record_classes[signed_rdtype]
        signed_records_text = self.unverified_cache[domain][rdclass][signed_rdtype]
        # logger.debug("Verifying signature of %s %r: %r", signed_rdtype, domain, signed_records_text)
        signed_records = [record_class(record).to_wire() for record in signed_records_text]
        # Sort the records according to the canonical ordering
        signed_records.sort()

        assert rdtype_content
        has_been_verified = False
        for rrsig_text in rdtype_content:
            rrsig = RRSigRecord(signed_rdtype, rrsig_text)
            try:
                dnskey = self.find_dnskey(rrsig.signer, rrsig.keytag, refresh=refresh)
            except KeyError:
                # This happens when a record is signed by several DNSKEY and
                # only one of them is declared in the DS record.
                continue

            # Compute the RRSIG signed data
            rrsig_first_part = rrsig.to_wire_without_signature()
            rrsig_items = []
            for wire in signed_records:
                # RR(i) = owner | type | class | TTL | RDATA length | RDATA
                rrsig_items.append(dns_name_to_wire(domain) + struct.pack(
                    '>HHIH',
                    DNS_RDATA_TYPES[signed_rdtype],
                    DNS_RDATA_CLASSES[rdclass],
                    rrsig.orig_ttl, len(wire)) + wire)
            # print(domain, rdtype, rrsig_hashobj.hexdigest())
            if not dnskey.verify(rrsig_first_part + b''.join(rrsig_items), rrsig.signature):
                raise ValueError("Invalid signature for {} {}".format(rdtype, domain))

            logger.debug("verified '%s %s' (%d records) with %r",
                         signed_rdtype, domain, len(signed_records), rrsig)
            has_been_verified = True

        if not has_been_verified:
            logger.error("no DNS key found to verify %s %s", signed_rdtype, domain)
            return None

        # Copy the records
        if domain not in self.verified_cache:
            self.verified_cache[domain] = {}
        if rdclass not in self.verified_cache[domain]:
            self.verified_cache[domain][rdclass] = {}
        self.verified_cache[domain][rdclass][rdtype] = rdtype_content
        self.verified_cache[domain][rdclass][signed_rdtype] = signed_records_text

        keys_to_remove = ((domain, rdclass, rdtype), (domain, rdclass, signed_rdtype))
        # Return the to-be-removed keys, if asked
        if do_not_remove:
            return keys_to_remove
        for rm_domain, rm_rdclass, rm_rdtype in keys_to_remove:
            del self.unverified_cache[rm_domain][rm_rdclass][rm_rdtype]
            if not self.unverified_cache[rm_domain][rm_rdclass]:
                del self.unverified_cache[rm_domain][rm_rdclass]
            if not self.unverified_cache[rm_domain]:
                del self.unverified_cache[rm_domain]
        return None

    def verify_all_cached_records(self, refresh=False):
        """Verify records in the unverified cache"""
        keys_to_remove = set()
        for domain, domain_cache in self.unverified_cache.items():
            for rdclass, rdclass_content in domain_cache.items():
                for rdtype in rdclass_content.keys():
                    if rdtype.startswith('RRSIG '):
                        # Browse the RRSIG records to verify them
                        result = self.verify_cached_record(
                            domain, rdclass, rdtype,
                            refresh=refresh, do_not_remove=True)
                        if result is not None:
                            for item in result:
                                keys_to_remove.add(item)

        for domain, rdclass, rdtype in keys_to_remove:
            del self.unverified_cache[domain][rdclass][rdtype]
            if not self.unverified_cache[domain][rdclass]:
                del self.unverified_cache[domain][rdclass]
            if not self.unverified_cache[domain]:
                del self.unverified_cache[domain]

    def get_dns_records(self, domain, rdtype_text, refresh=False):
        """Get the DNS records for the specified (domain, type)"""
        if not domain.endswith('.'):
            domain += '.'
        if refresh and (domain, rdtype_text) not in self.refreshed_records:
            # Only perform each DNS query once
            self.refreshed_records.add((domain, rdtype_text))
            self._refresh_dns_records_online(domain, rdtype_text)
        try:
            return self.verified_cache[domain]['IN'][rdtype_text]
        except KeyError:
            return []

    def get_dnskeys(self, domain, refresh=False):
        """Get DNSKEY records"""
        records = self.get_dns_records(domain, 'DNSKEY', refresh=refresh)
        if records:
            return [DNSKeyRecord(r) for r in records]

        # Load the records which did not succeed the signature check
        try:
            unverified_records = self.unverified_cache[domain]['IN']['DNSKEY']
        except KeyError:
            return []

        if domain == '.':
            # Bootstrap root DNS keys using the unverified cache
            return [DNSKeyRecord(r) for r in unverified_records]

        # Try to get a DS record to verify the DNS keys
        delegations = self.get_ds(domain, refresh=refresh)
        dnskeys = []
        for record_text in unverified_records:
            dnskey = DNSKeyRecord(record_text)
            has_been_validated = False
            for ds_record in delegations:
                if ds_record.key_tag == dnskey.key_tag and ds_record.verify_key(domain, dnskey):
                    logger.debug("using DS record (%s) to trust DNSKEY for %s: %r",
                                 ds_record.digest_desc, domain, dnskey)
                    has_been_validated = True
            if has_been_validated:
                dnskeys.append(dnskey)
        return dnskeys

    def find_dnskey(self, domain, keytag, refresh=False):
        """Get a DNSKEY by its keytag"""
        for dnskey in self.get_dnskeys(domain, refresh=refresh):
            if dnskey.key_tag == keytag:
                return dnskey
        raise KeyError("Unable to find DNSKEY({}, {})".format(repr(domain), keytag))

    def get_ds(self, domain, refresh=False):
        """Get DS records"""
        records = self.get_dns_records(domain, 'DS', refresh=refresh)
        return [DSRecord(r) for r in records]


def verify_dnssec(dns_cache, domain, refresh=False):
    """Verify the DNSSEC chain to a domain"""
    dns_keys = dns_cache.get_dnskeys(domain, refresh=refresh)
    print("* {} DNSSEC keys:".format(domain))
    for k in dns_keys:
        print("  * {}".format(repr(k)))

    nameservers = dns_cache.get_dns_records(domain, 'NS', refresh=refresh)
    print("* {} nameservers:".format(domain))
    for ns in nameservers:
        print("  * {}".format(ns))
        ipv4_addresses = dns_cache.get_dns_records(ns, 'A', refresh=refresh)
        ipv6_addresses = dns_cache.get_dns_records(ns, 'AAAA', refresh=refresh)
        for addr in ipv4_addresses:
            print("    * IPv4: {}".format(addr))
        for addr in ipv6_addresses:
            print("    * IPv6: {}".format(addr))
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify DNSSEC configuration")
    parser.add_argument('domains', metavar="DOMAIN", nargs='*', type=str,
                        help="domain name to verify (by default: all TLDs)")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-r', '--refresh', action='store_true',
                        help="Refresh the local DNS cache")
    parser.add_argument('--update-tld-list', action='store_true',
                        help="Update the list of TLDs")
    parser.add_argument('--all-the-tld-of-the-internet', action='store_true',
                        help="Query all the available TLDs, just for the fun of doing this!")
    parser.add_argument('--use-cloudflare', action='store_true',
                        help="use Cloudflare nameservers")
    parser.add_argument('--use-google', action='store_true',
                        help="use Google nameservers")
    args = parser.parse_args(argv)

    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    if args.update_tld_list:
        update_tld_list_from_openprovider()

    if not HAVE_CRYPTO_ECDSA:
        logger.warning("Cryptodome.PublicKey.ECC is not available (please used PyCryptodome instead of PyCrypto)")

    if args.refresh and not HAVE_DNSPYTHON:
        parser.error("--refresh requires dnspython to be installed.")

    dns_cache = DNSCache(DNS_CACHE_PATH, use_cloudflare=args.use_cloudflare, use_google=args.use_google)

    # Verify TLDs if no domain has been provided, except if a special option was given
    if args.all_the_tld_of_the_internet:
        domains = load_tld_list(TLD_LIST_PATH)
    else:
        domains = args.domains or MOST_USED_TOP_LEVEL_DOMAINS

    is_successful = True
    for domain in domains:
        if not verify_dnssec(dns_cache, domain, refresh=args.refresh):
            is_successful = False

    # Save the updated cache
    if args.refresh:
        dns_cache.save()

    return 0 if is_successful else 1


if __name__ == '__main__':
    sys.exit(main())
