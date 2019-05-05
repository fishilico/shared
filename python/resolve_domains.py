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
"""Resolve a list DNS domains with a caching directory

Usage example to resolve domains using Google's DNS-over-HTTPS API, a list in
domains.txt, a cache in directory dns/, writing results in results.out.txt:

    ./resolve_all_domains.py -gsSO -o results.out.txt -d dns domains.txt

@author: Nicolas Iooss
@license: MIT
"""
import argparse
import binascii
import ipaddress
import json
from pathlib import Path
import re
import ssl
import struct
import time
import urllib.parse
import urllib.request

try:
    import dns.resolver
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False
else:
    import dns
    import dns.flags
    import dns.rcode
    import dns.rdataclass
    import dns.rdatatype


# Types of DNS records that are resolved
DNS_TYPES = ('A', 'AAAA', 'MX', 'ANY', 'TXT', 'NS', 'PTR')

# Identifiers of record data types
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
DNS_TYPE_ITOA = dict((v, k) for k, v in DNS_RDATA_TYPES.items())

DNS_RESPONSE_CODES = {
    0: 'NOERROR',  # DNS Query completed successfully
    1: 'FORMERR',  # DNS Query Format Error
    2: 'SERVFAIL',  # Server failed to complete the DNS request
    3: 'NXDOMAIN',  # Domain name does not exist
    5: 'REFUSED',  # The server refused to answer for the query
}


def dns_sortkey(name):
    """Get the sort key of a domain name"""
    return name.split('.')[::-1]


class Resolver:
    def __init__(self, cache_directory, time_sleep=1, use_google=False, no_ssl=False):
        self.cache_directory = cache_directory
        self.time_sleep = time_sleep
        self.use_google = use_google
        self.no_ssl = no_ssl
        self.dns_records = None
        self.is_cache_dirty = True

    def load_cache(self, if_dirty=True):
        """Load cached DNS results from the cache directory"""
        if if_dirty and not self.is_cache_dirty:
            # Do not reload the cache if it has not been modified
            return

        self.dns_records = set()
        for filepath in self.cache_directory.glob('*.json'):
            with open(filepath, 'r') as fjson:
                json_data = json.load(fjson)

            # Ignore failed responses
            rcode_name = DNS_RESPONSE_CODES.get(json_data['Status'])
            if rcode_name in ('SERVFAIL', 'NXDOMAIN', 'REFUSED'):
                continue
            if rcode_name != 'NOERROR':
                raise ValueError("Invalid status {} ({}) in {}".format(
                    json_data['Status'], rcode_name, repr(filepath)))

            # Ignore empty responses
            if 'Answer' not in json_data:
                continue

            for answer in json_data['Answer']:
                asc_type = DNS_TYPE_ITOA[answer['type']]
                self.dns_records.add((answer['name'], asc_type, answer['data']))

                # Add fake reverse-PTR entry
                if asc_type == 'PTR':
                    matches = re.match(r'^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\.in-addr\.arpa\.$', answer['name'])
                    if matches:
                        # IPv4 PTR record
                        # Filter-out useless reverse names that include the IP address
                        if answer['data'].endswith('.rev.sfr.net.'):
                            if answer['data'] == answer['name'][:-len('.in-addr.arpa.')] + '.rev.sfr.net.':
                                continue
                        ip_addr = '.'.join(matches.groups()[::-1])
                        self.dns_records.add((answer['data'], 'rPTR', ip_addr))
                        continue

                    matches = re.match(r'^(([0-9a-f]+\.){32})ip6\.arpa\.$', answer['name'])
                    if matches:
                        packed_addr = binascii.unhexlify(matches.group(1).replace('.', '')[::-1])
                        ip_addr_expanded = ':'.join(
                            '{:04x}'.format(x) for x in struct.unpack('>8H', packed_addr))
                        ip_addr = ipaddress.IPv6Address(ip_addr_expanded).compressed
                        self.dns_records.add((answer['data'], 'rPTR', ip_addr))
                        continue

                    raise ValueError("Invalid PTR record name {}".format(repr(answer['name'])))

        self.is_cache_dirty = False

    def resolve_in_cache(self, domain, rtype, skip_if_loaded=False):
        """Resolve a domain name, writing the result in a cache file

        skip_if_loaded: skip the resolution if the domain is already loaded,
            even when there is no matching file in the cache directory.
        """
        domain = domain.strip('.')
        if skip_if_loaded:
            if any(x[1] == rtype and x[0] == domain for x in self.dns_records):
                return

        cache_file = self.cache_directory / '{}_{}.json'.format(domain, rtype)
        if cache_file.exists():
            return
        if self.use_google:
            response = self.query_google(domain, rtype)
        else:
            response = self.query_dns(domain, rtype)

        if not response:
            return

        # Write the cache file
        response = response.strip(b'\n')
        with open(cache_file, 'wb') as fout:
            fout.write(response)
            fout.write(b'\n')

        self.is_cache_dirty = True

        # Sleep after the DNS query
        if self.time_sleep:
            time.sleep(self.time_sleep)

    @staticmethod
    def get_ptr_name_for_ip(ip_addr, version=None):
        """Get the PTR domain name matching an IP address"""
        if hasattr(ip_addr, 'reverse_pointer'):
            # Python 3.5 introduced a property to compute the PTR name
            return ip_addr.reverse_pointer
        if isinstance(ip_addr, ipaddress.IPv4Address):
            return '{0[3]}.{0[2]}.{0[1]}.{0[0]}.in-addr.arpa.'.format(struct.unpack('BBBB', ip_addr.packed))
        if isinstance(ip_addr, ipaddress.IPv6Address):
            addr_hex = binascii.hexlify(ip_addr.packed).decode('ascii')
            return '{}.ip6.arpa.'.format('.'.join(addr_hex[::-1]))

        # Here, ip_addr has to be a string.
        if version is None:
            # Guess the version from the IP address
            version = 6 if ':' in ip_addr else 4
        if version == 4:
            return '{0[3]}.{0[2]}.{0[1]}.{0[0]}.in-addr.arpa.'.format(ip_addr.split('.'))
        if version == 6:
            addr_hex = binascii.hexlify(ipaddress.IPv6Address(ip_addr).packed).decode('ascii')
            return '{}.ip6.arpa.'.format('.'.join(addr_hex[::-1]))
        raise ValueError("Unknown IP version {}".format(repr(version)))

    def resolve_ip(self, ip_addr, version=None):
        """Resolve an IP address by querying a PTR record"""
        domain = self.get_ptr_name_for_ip(ip_addr, version)
        return self.resolve_in_cache(domain, 'PTR', skip_if_loaded=True)

    def query_dns(self, domain, rdtype_text):
        if not HAVE_DNSPYTHON:
            raise RuntimeError("Using DNS requires dnspython. Either install it or use -g to use Google DNS API")

        # dnspython does not like DNS metaqueries such as ANY requests
        if rdtype_text == 'ANY':
            print("Refusing to query DNS for {} <{}> (dnspython does not like it)".format(domain, rdtype_text))
            return None

        print("Querying DNS for {} <{}>...".format(domain, rdtype_text))
        resolver = dns.resolver.Resolver()
        resolver.use_edns(0, dns.flags.DO, 4096)
        dot_domain = domain + '.'
        rdtype = dns.rdatatype.from_text(rdtype_text)
        rdclass = dns.rdataclass.IN

        result = {
            'Status': 0,
            'Question': [
                {
                    'name': dot_domain,
                    'type': rdtype,
                },
            ],
            'Answer': [],
        }
        try:
            answers = resolver.query(dot_domain, rdtype, rdclass, True)
        except dns.resolver.NoAnswer:
            pass  # Empty answer is successful
        except dns.resolver.NXDOMAIN:
            assert dns.rcode.NXDOMAIN == 3
            result['Status'] = 3
        else:
            result['Flags'] = {
                'raw': answers.response.flags,
                'QR': bool(answers.response.flags & dns.flags.QR),  # Query Response (0x8000)
                'AA': bool(answers.response.flags & dns.flags.AA),  # Authoritative Answer (0x0400)
                'TC': bool(answers.response.flags & dns.flags.TC),  # Truncated Response (0x0200)
                'RD': bool(answers.response.flags & dns.flags.RD),  # Recursion Desired (0x0100)
                'RA': bool(answers.response.flags & dns.flags.RA),  # Recursion Available (0x0080)
                'AD': bool(answers.response.flags & dns.flags.AD),  # Authentic Data (0x0020)
                'CD': bool(answers.response.flags & dns.flags.CD),  # Checking Disabled (0x0010)
            }
            result['Answer'] = [
                {
                    'name': answers.name.to_text(omit_final_dot=False),
                    'type': answer.rdtype,
                    'TTL': answers.ttl,
                    'data': answer.to_text(),
                }
                for answer in answers
            ]

        return json.dumps(result).encode('ascii')

    def query_google(self, domain, rtype):
        """Perform a DNS query using https://dns.google.com/ API"""
        print("Querying dns.google.com for {} <{}>...".format(domain, rtype))
        params = {
            'name': domain,
            'type': rtype,
        }
        url = 'https://dns.google.com/resolve?' + urllib.parse.urlencode(params)
        ctx = ssl.create_default_context()
        if self.no_ssl:
            # Disable HTTPS certificate verification, for example when recording
            # the requests using a HTTPS proxy such as BurpSuite.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        req = urllib.request.Request(
            url,
            headers={
                'Accept': 'application/json, text/plain, */*',
                'Connection': 'close',
            })
        with opener.open(req) as resp:
            if resp.status not in (200, 204):
                raise ValueError("Request to {} returned HTTP status {}".format(url, resp.status))
            content_length = resp.getheader('Content-Length')
            if content_length:
                data = resp.read(int(content_length))
            else:
                data = resp.read()
        if not data:
            raise ValueError("No data in response to {}".format(url))
        return data

    def dump_records(self, hide_dnssec=False):
        """Enumerate the DNS records"""
        comments_for_data = {}

        def add_comment(key, comment):
            if key not in comments_for_data:
                comments_for_data[key] = set()
            comments_for_data[key].add(comment)

        max_domain_len = 0
        for domain, rtype, data in self.dns_records:
            if hide_dnssec and rtype in ('DNSKEY', 'NSEC3PARAM', 'NSEC3', 'RRSIG'):
                continue
            if rtype != 'PTR' and max_domain_len < len(domain):
                # Ignore long PTR records in max_domain_len computation
                max_domain_len = len(domain)
            if rtype in ('A', 'AAAA', 'rPTR'):
                if domain.endswith('.hosting.ovh.net.'):
                    add_comment(data, 'OVH shared hosting')
            if rtype == 'MX':
                if data.endswith('.ovh.net.'):
                    add_comment(data, 'OVH mail server')
            if rtype == 'NS':
                if data.endswith('.ovh.net.'):
                    add_comment(data, 'OVH DNS server')
            if rtype == 'PTR':
                if data.endswith('.hosting.ovh.net.'):
                    add_comment(data, 'OVH shared hosting')

        # Describe known providers.
        # Sort by domain name, and place rPTR entries right after A and AAAA ones.
        items = sorted(
            self.dns_records,
            key=lambda x: (dns_sortkey(x[0]), x[1].replace('rPTR', 'ArPTR'), x[2]))
        for domain, rtype, data in items:
            if hide_dnssec and rtype in ('DNSKEY', 'NSEC3PARAM', 'NSEC3', 'RRSIG'):
                continue
            padding = ' ' * (max_domain_len - len(domain)) if len(domain) < max_domain_len else ''
            line = '{}{} {:6} {}'.format(padding, domain, rtype, data)

            comments = comments_for_data.get(data)
            if comments:
                line += '  # ' + ', '.join(sorted(comments))
            yield line


def main(argv=None):
    parser = argparse.ArgumentParser(description="Resolve DNS records")
    parser.add_argument('file', metavar="DOMAINS_FILE", type=Path,
                        help="file containing a list of domains to resolve")
    parser.add_argument('-d', '--directory', type=Path,
                        help="directory where DNS results are cached")
    parser.add_argument('-D', '--hide-dnssec', action='store_true',
                        help="hide entries related to DNSSEC")
    parser.add_argument('-F', '--filter-exist', action='store_true',
                        help="filter-out non-existing domains from the input file")
    parser.add_argument('-g', '--use-google', action='store_true',
                        help="use https://dns.google.com/ API")
    parser.add_argument('-o', '--output', type=Path,
                        help="file where the DNS entries are written")
    parser.add_argument('-O', '--stdout', action='store_true',
                        help="print the results, when a file is also written")
    parser.add_argument('-i', '--ipaddr', metavar="IP_NETWORK",
                        nargs='*', type=ipaddress.ip_network,
                        help="resolve reverse (PTR) records for the IP addresses")
    parser.add_argument('-s', '--sort', action='store_true',
                        help="sort the domains of the input file")
    parser.add_argument('-S', '--no-ssl', action='store_true',
                        help="disable security of HTTPS queries")
    parser.add_argument('-t', '--time-sleep', type=int, default=1,
                        help="number of seconds to sleep between DNS queries")
    args = parser.parse_args(argv)

    if args.directory is None:
        parser.error("please provide a cache directory with option -d/--directory")

    # Load the list of domains
    with open(args.file, 'r') as fdomains:
        domains = [l.strip().rstrip('.') for l in fdomains.readlines()]

    if args.sort:
        sorted_domains = sorted(set(domains), key=dns_sortkey)
        if sorted_domains != domains:
            # Write the sorted list back
            with open(args.file, 'w') as fout:
                fout.write(''.join((d + '\n') for d in sorted_domains))
        domains = sorted_domains

    # Create the cache directory, if it does not exist
    args.directory.mkdir(exist_ok=True)

    resolver = Resolver(
        cache_directory=args.directory,
        time_sleep=args.time_sleep,
        use_google=args.use_google,
        no_ssl=args.no_ssl,
    )

    # Fill the cache
    for domain in domains:
        for rtype in DNS_TYPES:
            # Do not resolve PTR for normal domains
            if rtype != 'PTR':
                resolver.resolve_in_cache(domain, rtype)

    # Load the cache
    resolver.load_cache()

    # Resolve PTR records given on the command line
    if args.ipaddr:
        for ip_net in args.ipaddr:
            resolver.resolve_ip(ip_net.network_address)
            if ip_net.num_addresses >= 2:
                for ip_addr in ip_net.hosts():
                    resolver.resolve_ip(ip_addr)
                resolver.resolve_ip(ip_net.broadcast_address)
        resolver.load_cache(if_dirty=True)

    # Get all the A records, in order to get PTR
    all_ipv4_addresses = set(x[2] for x in resolver.dns_records if x[1] == 'A')
    for ip_addr in all_ipv4_addresses:
        resolver.resolve_ip(ip_addr, version=4)

    # Get all the AAAA records, in order to get PTR
    all_ipv6_addresses = set(x[2] for x in resolver.dns_records if x[1] == 'AAAA')
    for ip_addr in all_ipv6_addresses:
        resolver.resolve_ip(ip_addr, version=6)

    # Reload the cache, if needed
    resolver.load_cache(if_dirty=True)

    # Filter-out non-existing domains from the input file
    if args.filter_exist:
        found_domains = set(x[0].rstrip('.') for x in resolver.dns_records)
        sorted_domains = sorted(set(domains).intersection(found_domains), key=dns_sortkey)
        if sorted_domains != domains:
            # Write the sorted list back
            with open(args.file, 'w') as fout:
                fout.write(''.join((d + '\n') for d in sorted_domains))

    # Produce the output
    if args.output:
        with open(args.output, 'w') as fout:
            for line in resolver.dump_records(hide_dnssec=args.hide_dnssec):
                fout.write(line + '\n')

    if args.stdout or not args.output:
        for line in resolver.dump_records(hide_dnssec=args.hide_dnssec):
            print(line)


if __name__ == '__main__':
    main()
