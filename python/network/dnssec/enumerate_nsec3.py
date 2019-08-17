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
"""Enumerate a DNS domain using NSEC3 records (Next Secure)

Documentation:
* https://tools.ietf.org/html/rfc5155
  DNS Security (DNSSEC) Hashed Authenticated Denial of Existence

Similar tool:
* https://github.com/anonion0/nsec3map
"""
import argparse
import base64
import binascii
import errno
import hashlib
import itertools
import logging
import struct
import subprocess
import sys


logger = logging.getLogger(__name__)


# Hash algorithms for NSEC3
NSEC3_HASH_ALG = {
    1: 'SHA1',  # https://tools.ietf.org/html/rfc5155#section-11
}


def dns_name_to_wire(domain_name):
    """Transform a domain name to wire-format

    cf. https://tools.ietf.org/html/rfc5155#section-5
    (section "Calculation of the Hash")
    """
    if domain_name == '.':
        return b'\0'
    assert domain_name.endswith('.')
    labels = domain_name.encode('ascii').lower().split(b'.')
    return b''.join(struct.pack('B', len(x)) + x for x in labels)


BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
BASE32HEX_ALPHABET = '0123456789abcdefghijklmnopqrstuv'
assert len(BASE32_ALPHABET) == 32
assert len(BASE32HEX_ALPHABET) == 32
BASE32_TO_HEX_MAP = dict(zip(BASE32_ALPHABET, BASE32HEX_ALPHABET))
BASE32_FROM_HEX_MAP = dict(zip(BASE32HEX_ALPHABET, BASE32_ALPHABET))


def nsec3_hash(domain_name, hash_alg, iterations, salt):
    """Hash a domain name according to DNSSEC NSEC3 algorithm"""
    wire_name = dns_name_to_wire(domain_name)
    if hash_alg == 1:
        # SHA-1
        current_hash = hashlib.sha1(wire_name + salt).digest()
        for _ in range(iterations):
            current_hash = hashlib.sha1(current_hash + salt).digest()
    else:
        raise NotImplementedError("Unimplemented hash algorithm {}".format(hash_alg))

    # Encode the hash in base32hex
    b32hash = base64.b32encode(current_hash).decode('ascii')
    b32hex_hash = ''.join(BASE32_TO_HEX_MAP[c] for c in b32hash)
    return b32hex_hash


def base32hex_decode(hex_hash):
    """Decode an hash encoded in base32hex"""
    b32hash = ''.join(BASE32_FROM_HEX_MAP[c] for c in hex_hash.lower())
    return base64.b32decode(b32hash)


class NSec3ParamRecord(object):
    """NSEC3PARAM record"""
    def __init__(self, domain, hash_algorithm, flags, iterations, salt):
        self.domain = domain
        self.hash_algorithm = hash_algorithm
        self.hash_alg_name = NSEC3_HASH_ALG.get(
            self.hash_algorithm, 'UNKNOWN-{}'.format(self.hash_algorithm))
        self.flags = flags
        self.iterations = iterations
        self.salt = salt
        self.hex_salt = binascii.hexlify(salt).decode('ascii')

    def __repr__(self):
        return '<{}(domain={}, alg={}, {}iterations={}, salt=0x{}>'.format(
            self.__class__.__name__,
            repr(self.domain),
            self.hash_alg_name,
            'flags={}, '.format(self.flags) if self.flags else '',
            self.iterations,
            self.hex_salt,
        )

    def hash(self, domain_name):
        """Compute the hash of a domain name"""
        return nsec3_hash(domain_name, self.hash_algorithm, self.iterations, self.salt)

    def to_dns_line(self):
        """Write a line like a BIND entry or a result of command 'dig'"""
        return '{} 60 IN NSEC3PARAM {} {} {} {}'.format(
            self.domain,
            self.hash_algorithm,
            self.flags,
            self.iterations,
            self.hex_salt,
        )


class NSec3Record(object):
    """NSEC3 record"""
    def __init__(self, domain, hash_algorithm, flags, iterations, salt, next_hashed, record_types):
        self.domain = domain.lower()
        self.hash_algorithm = hash_algorithm
        self.hash_alg_name = NSEC3_HASH_ALG.get(
            self.hash_algorithm, 'UNKNOWN-{}'.format(self.hash_algorithm))
        self.flags = flags
        self.iterations = iterations
        self.salt = salt
        self.hex_salt = binascii.hexlify(salt).decode('ascii')
        self.next_hashed = next_hashed.lower()
        self.record_types = record_types

        # Parse the hash
        self.domain_hash, self.zone_name = self.domain.split('.', 1)
        self.next_domain = '{}.{}'.format(next_hashed, self.zone_name)
        if self.hash_algorithm == 1:
            # SHA-1, in base32hex: 32 characters
            assert len(self.domain_hash) == 32, "Invalid SHA-1 NSEC3 domain %r" % domain
            assert len(self.next_hashed) == 32, "Invalid SHA-1 NSEC3 next hashed %r" % self.next_hashed
        else:
            raise NotImplementedError("Unimplemented hash algorithm {}".format(self.hash_alg_name))

    def __repr__(self):
        return '<{}(domain={}, alg={}, {}iterations={}, salt=0x{}, next={}, types=[{}]>'.format(
            self.__class__.__name__,
            repr(self.domain),
            self.hash_alg_name,
            'flags={}, '.format(self.flags) if self.flags else '',
            self.iterations,
            self.hex_salt,
            self.next_hashed,
            ','.join(self.record_types),
        )

    def to_dns_line(self):
        """Write a line like a BIND entry or a result of command 'dig'"""
        return '{} 60 IN NSEC3 {} {} {} {} {} {}'.format(
            self.domain,
            self.hash_algorithm,
            self.flags,
            self.iterations,
            self.hex_salt,
            self.next_hashed,
            ' '.join(self.record_types),
        )


def build_dns_record_object(domain, rdtype, fields):
    """Craft an object describing a DNS record"""
    if rdtype == 'NSEC3PARAM' and len(fields) == 4:
        try:
            return NSec3ParamRecord(
                domain=domain,
                hash_algorithm=int(fields[0]),
                flags=int(fields[1]),
                iterations=int(fields[2]),
                salt=binascii.unhexlify(fields[3]),
            )
        except ValueError:
            pass
    elif rdtype == 'NSEC3' and len(fields) >= 5:
        try:
            return NSec3Record(
                domain=domain,
                hash_algorithm=int(fields[0]),
                flags=int(fields[1]),
                iterations=int(fields[2]),
                salt=binascii.unhexlify(fields[3]),
                next_hashed=fields[4],
                record_types=fields[5:],
            )
        except ValueError:
            pass

    logger.error("unknown %s record for %r: %r", rdtype, domain, fields)
    raise ValueError


def query_dns(domain, request_type, response_types):
    """Query the DNS server for a some records for the specified domain"""
    # Try using drill or dig
    for prgm in (['drill', '-D'], ['dig', '+dnssec']):
        cmdline = prgm + [domain, request_type]
        logger.debug("Running %r", ' '.join(cmdline))
        try:
            cmd_output = subprocess.check_output(cmdline)
        except OSError as exc:
            # Ignore if the program is not installed
            if exc.errno != errno.ENOENT:
                raise
        else:
            result = []
            for raw_line in cmd_output.splitlines():
                line = raw_line.strip().decode('utf-8')
                if not line or line.startswith(';'):
                    continue
                fields = line.strip().split(None)
                assert fields[2] == 'IN', "Unknown DNS class {}".format(fields[2])
                if fields[3] in response_types:
                    # logger.debug("Parsing %r", line)
                    result.append(build_dns_record_object(
                        domain=fields[0],
                        rdtype=fields[3],
                        fields=fields[4:]))
            return result

    logger.fatal("Unable to find a program to perform DNS queries (dig or drill)")
    raise RuntimeError("No DNS program available")


def load_dns_cache_file(cache_file):
    """Load a file containing DNS records"""
    cache = {
        '_file': cache_file,
    }
    try:
        with open(cache_file, 'r') as fd:
            logger.debug("Loading DNS cache from %r", cache_file)
            for line in fd:
                if line.startswith((';', '#')):
                    continue
                fields = line.strip().split(None)
                assert fields[2] == 'IN', "Unknown DNS class {}".format(fields[2])
                rdtype = fields[3]
                record = build_dns_record_object(
                    domain=fields[0],
                    rdtype=rdtype,
                    fields=fields[4:])
                if rdtype not in cache:
                    cache[rdtype] = {}
                if record.domain not in cache[rdtype]:
                    cache[rdtype][record.domain] = []
                cache[rdtype][record.domain].append(record)
    except IOError as exc:
        if exc.errno != errno.ENOENT:
            raise
    return cache


def save_dns_cache_file(dns_cache):
    """Save a file with resolved DNS records"""
    cache_file = dns_cache['_file']
    if not cache_file:
        # No cache
        return
    logger.debug("Saving DNS cache to %r", cache_file)
    records = set()
    for rdtype, cache_for_records in dns_cache.items():
        if rdtype == '_file':
            continue
        for cache_for_domains in cache_for_records.values():
            for record in cache_for_domains:
                records.add(record.to_dns_line() + '\n')
    with open(cache_file, 'w') as fd:
        fd.write(''.join(sorted(records)))


def query_cached_dns(domain, rdtype, dns_cache):
    try:
        return dns_cache[rdtype][domain]
    except KeyError:
        pass
    results = query_dns(domain, rdtype, (rdtype, ))

    if results:
        # Cache the results
        if rdtype not in dns_cache:
            dns_cache[rdtype] = {}
        for record in results:
            if record.domain not in dns_cache[rdtype]:
                dns_cache[rdtype][record.domain] = []
            dns_cache[rdtype][record.domain].append(record)
    return results


class Nsec3ForZone(object):
    """Maintain a list of NSEC3 records for a given DNS zone

    It is a kind of interval list of known NSEC3 records
    """
    def __init__(self, nsec3param, dns_cache):
        assert isinstance(nsec3param, NSec3ParamRecord)
        self.nsec3param = nsec3param
        self.zone_name = nsec3param.domain
        known_nsec3 = set()
        self.known_nsec3_keys = set()
        for nsec3_records in dns_cache.get('NSEC3', {}).values():
            for nsec3 in nsec3_records:
                if nsec3.zone_name == self.zone_name:
                    known_nsec3.add((nsec3.domain_hash, nsec3.next_hashed))
                    self.known_nsec3_keys.add(nsec3.domain_hash)
        # Use a sorted list as this structure should not be large, and the
        # query time is more important to optimize than the insert time.
        self.known_nsec3 = sorted(known_nsec3)

        # Is the last one looping back
        self.is_looping = self.known_nsec3[-1][0] > self.known_nsec3[-1][1]
        assert all(tup[0] < tup[1] for tup in self.known_nsec3[:-1])

    def __len__(self):
        assert len(self.known_nsec3_keys) == len(self.known_nsec3)
        return len(self.known_nsec3_keys)

    def count_incomplete(self):
        """Return the number of NSEC3 entries which are breaking the chain"""
        known_next = set(tup[1] for tup in self.known_nsec3)
        incomplete = known_next - self.known_nsec3_keys
        return len(incomplete)

    def find_interval_for_hash(self, domain_hash):
        """Find the given hash in the known NSEC3 records"""
        interval_firstpos = 0
        interval_lastpos = len(self.known_nsec3) - 1
        interval_lastitem = self.known_nsec3[interval_lastpos][1]
        if self.is_looping:
            if domain_hash >= self.known_nsec3[interval_lastpos][0]:
                return self.known_nsec3[interval_lastpos]
            if domain_hash < interval_lastitem:
                return self.known_nsec3[interval_lastpos]
        else:
            if domain_hash >= interval_lastitem:
                return None
        if domain_hash < self.known_nsec3[0][0]:
            return None

        # Dichotomy
        while interval_firstpos <= interval_lastpos:
            middle_pos = (interval_firstpos + interval_lastpos) // 2
            middle_item_tuple = self.known_nsec3[middle_pos]
            if domain_hash < middle_item_tuple[0]:
                interval_lastpos = middle_pos - 1
            elif domain_hash > middle_item_tuple[1]:
                interval_firstpos = middle_pos + 1
            else:
                return middle_item_tuple
        return None

    def test_base_domain(self, domain_base_name, dns_cache):
        """Ensure that the given base domain is covered by an NSEC3 entry"""
        # Compute the hash for the domain name
        assert domain_base_name[-1] != '.'
        domain_name = '{}.{}'.format(domain_base_name, self.zone_name)
        domain_hash = self.nsec3param.hash(domain_name)
        if self.find_interval_for_hash(domain_hash):
            return

        # Query the NSEC3 records
        found_nsec3 = query_cached_dns(domain_name, 'NSEC3', dns_cache)
        if not found_nsec3:
            logger.warning("No NSEC3 record for %s, it may be a valid domain name.", domain_name)
            return
        for nsec3 in found_nsec3:
            if nsec3.zone_name != self.zone_name:
                logger.warning("Received a DNSSEC NSEC3 record for an unexpected zone: %r != %r",
                               nsec3.zone_name, self.zone_name)
            elif nsec3.domain_hash not in self.known_nsec3_keys:
                logger.debug("Adding to NSEC3 cache: %r", nsec3)
                self.known_nsec3_keys.add(nsec3.domain_hash)
                self.known_nsec3.append((nsec3.domain_hash, nsec3.next_hashed))
        self.known_nsec3.sort()
        if not self.is_looping:
            self.is_looping = self.known_nsec3[-1][0] > self.known_nsec3[-1][1]
        assert all(tup[0] < tup[1] for tup in self.known_nsec3[:-1])
        if not self.find_interval_for_hash(domain_hash):
            logger.warning("The NSEC3 record for %r has not been cached.", domain_name)


def enumerate_nsec3(domain, dns_cache, output_format, wordlist=None):
    """Enumerate the NSEC3 entries of a domain"""
    if not domain.endswith('.'):
        domain += '.'

    # Show NSEC3PARAM
    results = query_cached_dns(domain, 'NSEC3PARAM', dns_cache)
    nsec3param = None
    if not results:
        logger.warning("No NSEC3PARAM record for %r", domain)
    else:
        if len(results) > 1:
            logger.warning("Multiple NSEC3PARAM record for %r", domain)
        for res in results:
            logger.info("NSEC3PARAM for %s: %d iterations of %s with salt 0x%s",
                        res.domain,
                        res.iterations,
                        res.hash_alg_name,
                        res.hex_salt)
        nsec3param = results[0]

    # Start with a NSEC3 for the domain
    found_nsec3 = query_cached_dns(domain, 'NSEC3', dns_cache)
    if not found_nsec3:
        logger.error("No NSEC3 record for %r", domain)
        return False

    if len(found_nsec3) > 1:
        logger.warning("Multiple NSEC3 record for %r: it does not exist?", domain)
        logger.debug("Received NSEC3 records: %r", found_nsec3)
        return False

    domain_nsec3 = found_nsec3[0]
    zone_name = domain_nsec3.zone_name

    # Ensure that NSEC3 hash is correct
    expected_hash = nsec3_hash(domain, domain_nsec3.hash_algorithm, domain_nsec3.iterations, domain_nsec3.salt)
    if domain_nsec3.domain_hash != expected_hash:
        logger.error("Unexpected NSEC3 hash for %r: %r != %r", domain, domain_nsec3.domain_hash, expected_hash)
        return False
    logger.debug("Good NSEC3 hash for %r (%r)", domain, expected_hash)

    if nsec3param is None:
        # This may happen when running on an entry of a DNS zone
        print("{} is a domain depending on zone {} (NSEC3 hash {})".format(domain, zone_name, expected_hash))
        return True

    # Gather all the known NSEC3 records from the cache, to build known intervals
    nsec3zone = Nsec3ForZone(nsec3param, dns_cache)
    assert nsec3zone.zone_name == domain, "Mismatched domain name for DNS zone"
    assert any(domain_nsec3.domain_hash == x[0] for x in nsec3zone.known_nsec3), "Inconsistent cache, missing domain"

    # Start recording the cache. It is fails, better do it now that after the bruteforce
    save_dns_cache_file(dns_cache)

    if nsec3zone.count_incomplete() == 0:
        logger.info("Got %d entries in NSEC3 DNS cache for %s, which build a complete chain!",
                    len(nsec3zone), zone_name)
    else:
        logger.info("Got %d entries in NSEC3 DNS cache for %s before bruteforce (%d incomplete entries)",
                    len(nsec3zone), zone_name, nsec3zone.count_incomplete())

        # Bruteforce up to 4 letters domains
        dns_alphabet = 'abcdefghjiklmnopqrstuvwxyz0123456789'
        for domain_len in range(1, 5):
            if nsec3zone.count_incomplete() == 0:
                break
            for domain_letters in itertools.product(dns_alphabet, repeat=domain_len):
                domain_base_name = ''.join(domain_letters)
                nsec3zone.test_base_domain(domain_base_name, dns_cache)
            save_dns_cache_file(dns_cache)
            logger.info(
                "Got %d NSEC3 entries after bruteforcing %d-letter domains (%d incomplete)",
                len(nsec3zone), domain_len, nsec3zone.count_incomplete())

    # Let's guess some names
    known_hashes = {expected_hash: domain}
    for domain_len in range(1, 4):
        if len(known_hashes) == len(nsec3zone):
            break
        dns_alphabet = 'abcdefghjiklmnopqrstuvwxyz0123456789-_.'
        for domain_letters in itertools.product(dns_alphabet, repeat=domain_len):
            guessed_name = ''.join(domain_letters) + '.' + zone_name
            guessed_hash = nsec3param.hash(guessed_name)
            if guessed_hash in nsec3zone.known_nsec3_keys:
                known_hashes[guessed_hash] = guessed_name
    logger.debug("Guessed %d/%d names", len(known_hashes), len(nsec3zone))

    # Use the provided wordlist to recover names
    if wordlist:
        for word in wordlist:
            if len(known_hashes) == len(nsec3zone):
                break
            guessed_name = word + '.' + zone_name
            guessed_hash = nsec3param.hash(guessed_name)
            if guessed_hash in nsec3zone.known_nsec3_keys:
                known_hashes[guessed_hash] = guessed_name
        logger.debug("Found %d/%d names after wordlist", len(known_hashes), len(nsec3zone))

    if output_format == 'john':
        # Format the output in a format suitable for John The Ripper
        for hashes in nsec3zone.known_nsec3:
            hex_hash = binascii.hexlify(base32hex_decode(hashes[0])).decode('ascii')
            print("{}:$NSEC3${}${}${}${}".format(
                known_hashes.get(hashes[0], '?.{}'.format(domain)),
                nsec3param.iterations, nsec3param.hex_salt, hex_hash, domain))
        return True

    print("NSEC3 chain of {}:".format(domain))
    for idx, hashes in enumerate(nsec3zone.known_nsec3):
        known_name = known_hashes.get(hashes[0])
        if known_name:
            print("- [{0}] {1[0]} -> {1[1]} for {2}".format(idx, hashes, known_name))
        else:
            print("- [{0}] {1[0]} -> {1[1]}".format(idx, hashes))
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description="Enumerate DNS records using NSEC")
    parser.add_argument('domains', metavar="DOMAIN", nargs='+', type=str,
                        help="domain name from which the enumeration starts")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-c', '--cache-file', type=str,
                        help="use a file to cache DNS responses")
    parser.add_argument('-j', '--john', action='store_true',
                        help="output hashes in John The Ripper format")
    parser.add_argument('-w', '--wordlist', type=str,
                        help="list of domains to use to crack NSEC3 hashes")
    args = parser.parse_args(argv)

    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    dns_cache = load_dns_cache_file(args.cache_file) if args.cache_file else {}

    output_format = None
    if args.john:
        output_format = 'john'

    wordlist = None
    if args.wordlist:
        wordlist_entries = set()
        with open(args.wordlist, 'r') as fd:
            for line in fd:
                # For "a.b.c", add all possible sub-combinations to the wordlist
                line_parts = line.strip().split('.')
                for i_start in range(len(line_parts) - 1):
                    for i_end in range(i_start + 1, len(line_parts)):
                        wordlist_entries.add('.'.join(line_parts[i_start:i_end]))
        wordlist = sorted(wordlist_entries)

    for domain in args.domains:
        if not enumerate_nsec3(domain, dns_cache, output_format, wordlist=wordlist):
            return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
