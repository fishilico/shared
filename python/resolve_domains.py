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

    ./resolve_domains.py -gMOs -o dns_resolutions.out.txt -d cache_dns domains.txt

@author: Nicolas Iooss
@license: MIT
"""
import argparse
import binascii
import ipaddress
import itertools
import json
from pathlib import Path
import random
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
DNS_TYPES = ('A', 'AAAA', 'MX', 'NS', 'PTR', 'TXT', 'ANY')
DNS_SRV_TYPES = ('NS', 'SRV', 'TXT', 'ANY')

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
    'RESERVED-65534': 65534,
}
DNS_TYPE_ITOA = dict((v, k) for k, v in DNS_RDATA_TYPES.items())

DNS_RESPONSE_CODES = {
    0: 'NOERROR',  # DNS Query completed successfully
    1: 'FORMERR',  # DNS Query Format Error
    2: 'SERVFAIL',  # Server failed to complete the DNS request
    3: 'NXDOMAIN',  # Domain name does not exist
    5: 'REFUSED',  # The server refused to answer for the query
}


# Well-known prefixes seen on domain names
WELLKNOWN_PREFIXES = (
    '_domainkey',
    '_ipp._tcp',
    '_kerberos._tcp',
    '_kerberos._tcp.dc._msdcs',
    '_ldap._tcp',
    '_ldap._tcp.dc._msdcs',
    '_ldap._tcp.gc._msdcs',
    '_ldap._tcp.pdc._msdcs',
    '_ldaps._tcp',
    '_msdcs',
    'a',
    'about',
    'account',
    'admin',
    'agent',
    'alpha',
    'api',
    'app',
    'app1',
    'archive',
    'auth',
    'autodiscover',
    'b',
    'back',
    'backup',
    'bck',
    'beta',
    'bit',
    'bits',
    'blog',
    'bot',
    'business',
    'c',
    'cache',
    'calendar',
    'cdn',
    'chat',
    'code',
    'collect',
    'collectd',
    'com',
    'commute',
    'connect',
    'console',
    'corp',
    'cpanel',
    'cvs',
    'data',
    'database',
    'db',
    'dc1',
    'dc2',
    'dev',
    'developer',
    'dmz',
    'dns1',
    'dns2',
    'doc',
    'docs',
    'en',
    'eu',
    'euro',
    'ext',
    'extra',
    'extranet',
    'files',
    'fr',
    'free',
    'ftp',
    'gc._msdcs',
    'geo',
    'git',
    'gitlab',
    'google._domainkey',
    'grafana',
    'graph',
    'group',
    'help',
    'helpdesk',
    'hg',
    'icinga',
    'icingaweb',
    'identity',
    'idp',
    'imap',
    'ins',
    'inside',
    'int',
    'intra',
    'intranet',
    'irc',
    'jenkins',
    'job',
    'join',
    'list',
    'lists',
    'log',
    'login',
    'lyncdiscover',
    'mail',
    'mail1',
    'mail2',
    'master',
    'matrix',
    'mattermost',
    'mf1',
    'mfa',
    'mobility',
    'msoid',
    'mssql',
    'mx1',
    'mx2',
    'my',
    'mysql',
    'nagios',
    'name',
    'net',
    'new',
    'news',
    'ns1',
    'ns2',
    'ntp',
    'oauth',
    'old',
    'open',
    'opensource',
    'org',
    'outlook',
    'pass',
    'pdns',
    'phone',
    'phpmyadmin',
    'pki',
    'pop',
    'pop3',
    'pop3s',
    'portal',
    'prod',
    'product',
    'products',
    'proxy',
    'public',
    'publish',
    'qat',
    'qual',
    'queue',
    'rabbitmq',
    'random',
    'redis',
    'redmine',
    'register',
    'registry',
    'release',
    'releases',
    'repo',
    'rest',
    'rsa',
    'rss',
    'sap',
    'search',
    'secure',
    'share',
    'sharing',
    'shop',
    'sip',
    'smtp',
    'smtp1',
    'smtp2',
    'smtps',
    'sonar',
    'spf',
    'splunk',
    'sql',
    'ssl',
    'sso',
    'staff',
    'stat',
    'static',
    'stats',
    'sts',
    'subversion',
    'support',
    'svn',
    'test',
    'tls',
    'token',
    'tool',
    'tools',
    'torrent',
    'tracker',
    'uat',
    'uk',
    'us',
    'voip',
    'vpn',
    'web',
    'webchat',
    'webmail',
    'wifi',
    'wiki',
    'wildcard',
    'wireless',
    'www',
    'www1',
    'www3',
    'xyz',
    'zammad',
    'zero',
    'zeromq',
    'zimbra',
)


def get_comment_for_domain(domain):
    """Decribe a domain name to produce a comment"""
    if domain.endswith((
            '.akamaiedge.net.',
            '.akamaized.net',
            '.edgekey.net.',
            '.static.akamaitechnologies.com.')):
        return 'Akamai CDN'
    if domain.endswith('.amazonaws.com.'):
        return 'Amazon AWS'
    if domain.endswith('.cdn.cloudflare.net.'):
        return 'Cloudflare CDN'
    if domain.endswith('.mail.gandi.net.') or domain == 'webmail.gandi.net.':
        return 'Gandi mail hosting'
    if domain == 'webredir.vip.gandi.net.':
        return 'Gandi web forwarding hosting'
    if domain.endswith('.lync.com.'):
        return 'Microsoft Lync'
    if domain == 'clientconfig.microsoftonline-p.net.':
        # https://docs.microsoft.com/en-gb/office365/enterprise/external-domain-name-system-records
        return 'Microsoft Office 365 tenant'
    if domain.endswith(('.office.com.', '.office365.com.')):
        return 'Microsoft Office 365'
    if domain.endswith('.outlook.com.'):
        return 'Microsoft Outlook mail'
    if domain == 'redirect.ovh.net.':
        return 'OVH mail provider'
    if domain.endswith('.hosting.ovh.net.'):
        return 'OVH shared web hosting'
    if domain.endswith('.rev.sfr.net.'):
        return 'SFR provider'
    return None


def get_comment_for_record(domain, rtype, data):
    """Decribe a DNS record to produce a comment"""
    if rtype == 'PTR':
        # produce the same comment as for the reverse-PTR record
        return get_comment_for_domain(data)

    if rtype == 'CNAME':
        # Try describing the alias target
        return get_comment_for_domain(domain) or get_comment_for_domain(data)

    if rtype == 'MX':
        data = data.lower()
        if data.endswith(('.google.com.', '.googlemail.com.')):
            return 'Google mail server'
        if data.endswith('.outlook.com.'):
            return 'Microsoft Outlook mail server'
        if data.endswith('.outlook.com.'):
            return 'Microsoft Outlook mail server'
        if data.endswith('.pphosted.com.'):
            return 'Proofpoint mail server'

        # Try matching the name of MX servers
        matches = re.match(r'^[0-9]+\s+(\S+)$', data)
        if matches:
            return get_comment_for_domain(matches.group(1))

    if rtype == 'NS':
        if data.endswith('.gandi.net.'):
            return 'Gandi DNS server'
        if data.endswith('.ovh.net.'):
            return 'OVH DNS server'

    return get_comment_for_domain(domain)


def dns_sortkey(name):
    """Get the sort key of a domain name"""
    return name.lower().split('.')[::-1]


class Resolver:
    def __init__(self, cache_directory, time_sleep=1, use_google=False, no_ssl=False):
        self.cache_directory = cache_directory
        self.time_sleep = time_sleep
        self.use_google = use_google
        self.no_ssl = no_ssl
        self.dns_questions = None
        self.dns_records = None
        self.is_cache_dirty = True
        self.has_show_dnspython_any_warning = False
        self.load_cache(if_dirty=False)

    def load_cache(self, if_dirty=True):
        """Load cached DNS results from the cache directory"""
        if if_dirty and not self.is_cache_dirty:
            # Do not reload the cache if it has not been modified
            return

        self.dns_questions = set()
        self.dns_records = set()
        for filepath in self.cache_directory.glob('*.json'):
            with filepath.open(mode='r') as fjson:
                for line in fjson:
                    json_data = json.loads(line)

                    # Add the question to the list of asked ones
                    for question in json_data['Question']:
                        self.dns_questions.add(
                            (question['name'].lower().strip('.'), DNS_TYPE_ITOA[question['type']])
                        )

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
                            matches = re.match(
                                r'^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\.in-addr\.arpa\.$',
                                answer['name'])
                            if matches:
                                # IPv4 PTR record
                                ip_addr = '.'.join(matches.groups()[::-1])
                                self.dns_records.add((answer['data'], 'rPTR', ip_addr))
                                continue

                            matches = re.match(r'^(([0-9a-f]+\.){32})ip6\.arpa\.$', answer['name'])
                            if matches:
                                # IPv6 PTR record
                                packed_addr = binascii.unhexlify(matches.group(1).replace('.', '')[::-1])
                                ip_addr_expanded = ':'.join(
                                    '{:04x}'.format(x) for x in struct.unpack('>8H', packed_addr))
                                ip_addr = ipaddress.IPv6Address(ip_addr_expanded).compressed
                                self.dns_records.add((answer['data'], 'rPTR', ip_addr))
                                continue

                            print("Warning: invalid PTR record name {}".format(repr(answer['name'])))

        self.is_cache_dirty = False

    def merge_cache_files(self):
        """Merge all cache files into one"""
        # Load all the JSON records, and deduplicate them
        all_files = set()
        all_lines = set()
        for filepath in self.cache_directory.glob('*.json'):
            all_files.add(filepath)
            with filepath.open(mode='r') as fjson:
                for line in fjson:
                    all_lines.add(line.strip() + '\n')

        merged_file = self.cache_directory / 'all.json'
        with merged_file.open(mode='w') as fout:
            fout.write(''.join(sorted(all_lines)))
        for filepath in all_files:
            if filepath != merged_file:
                filepath.unlink()

    def resolve_in_cache(self, domain, rtype):
        """Resolve a domain name, writing the result in a cache file"""
        domain = domain.strip('.')
        # NB. use dns_questions instead of dns_records in order to perform
        # specific queries (A, AAAA, TXT, etc.) even after an ANY query.
        if (domain, rtype) in self.dns_questions:
            return

        cache_file = self.cache_directory / '{}_{}.json'.format(domain, rtype)
        if cache_file.exists():
            print("Warning: cache file exists for {} <{}> but was not loaded".format(domain, rtype))
            return

        if self.use_google:
            response = self.query_google(domain, rtype)
        else:
            response = self.query_dns(domain, rtype)

        if not response:
            return

        # Write the cache file
        response = response.strip(b'\n')
        with cache_file.open(mode='wb') as fout:
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
        return self.resolve_in_cache(domain, 'PTR')

    def query_dns(self, domain, rdtype_text):
        if not HAVE_DNSPYTHON:
            raise RuntimeError("Using DNS requires dnspython. Either install it or use -g to use Google DNS API")

        # dnspython does not like DNS metaqueries such as ANY requests
        if rdtype_text == 'ANY':
            if not self.has_show_dnspython_any_warning:
                print("Warning: refusing to query DNS for type ANY (dnspython does not like it)")
                self.has_show_dnspython_any_warning = True
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

        # Find out wildcard domains using resolutions for "b.domain",
        # "random.domain" and "xyz.domain"
        wildcard_detectors = ('b.', 'random.', 'xyz.')
        wildcard_witness = {}

        # Describe known providers
        for domain, rtype, data in self.dns_records:
            if hide_dnssec and rtype in ('DNSKEY', 'NSEC3PARAM', 'NSEC3', 'RRSIG'):
                continue
            comment = get_comment_for_record(domain, rtype, data)
            if comment:
                add_comment(data, comment)

            if domain.startswith(wildcard_detectors):
                wild_suffix = domain.split('.', 1)[1]
                if wild_suffix not in wildcard_witness:
                    wildcard_witness[wild_suffix] = {}
                if rtype not in wildcard_witness[wild_suffix]:
                    wildcard_witness[wild_suffix][rtype] = {}
                if domain not in wildcard_witness[wild_suffix][rtype]:
                    wildcard_witness[wild_suffix][rtype][domain] = set()
                wildcard_witness[wild_suffix][rtype][domain].add(data)

        # Compute wildcard records
        all_records = self.dns_records.copy()
        wildcard_records_by_data = {}
        for wild_suffix, suffix_types_witnesses in wildcard_witness.items():
            for rtype, witnesses in suffix_types_witnesses.items():
                if len(witnesses) != len(wildcard_detectors):
                    continue
                wild_several_data = None
                try:
                    for several_data in witnesses.values():
                        if wild_several_data is None:
                            wild_several_data = several_data
                        if wild_several_data != several_data:
                            raise ValueError
                except ValueError:
                    # Not a wildcard
                    break
                assert wild_several_data is not None
                # Add a wildcard record and filter-out existing ones
                for data in wild_several_data:
                    all_records.add(('*.' + wild_suffix, rtype, data))
                    # Identify wildcard records by their data
                    if (rtype, data) not in wildcard_records_by_data:
                        wildcard_records_by_data[(rtype, data)] = set()
                    wildcard_records_by_data[(rtype, data)].add(wild_suffix)

        # Filter-out wildcard records and compute the maximum length of a domain name
        max_domain_len = 0
        deleted_records = set()
        for domain, rtype, data in all_records:
            is_deleted = False
            for possible_wild_suffix in wildcard_records_by_data.get((rtype, data), []):
                if domain != '*.' + possible_wild_suffix and domain.endswith('.' + possible_wild_suffix):
                    deleted_records.add((domain, rtype, data))
                    is_deleted = True
                    continue
            if is_deleted:
                continue
            if rtype == 'PTR':
                # Ignore long PTR records in max_domain_len computation
                continue
            if max_domain_len < len(domain):
                max_domain_len = len(domain)

        for rec in deleted_records:
            all_records.remove(rec)

        # Sort by domain name, and place rPTR entries right after A and AAAA ones.
        items = sorted(
            all_records,
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
    parser.add_argument('-M', '--merge-cache', action='store_true',
                        help="merge cache files together")
    parser.add_argument('-p', '--prefixes', action='store_true',
                        help="add some well-known prefixes to the domains")
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
    with args.file.open(mode='r') as fdomains:
        raw_domains = [l.rstrip('\n') for l in fdomains.readlines()]
    domains = [l.strip().rstrip('.').lower() for l in raw_domains]

    if args.sort:
        domains_set = set(domains)
        if '' in domains_set:
            domains_set.remove('')
        sorted_domains = sorted(domains_set, key=dns_sortkey)
        if sorted_domains != raw_domains:
            # Write the sorted list back
            with args.file.open(mode='w') as fout:
                fout.write(''.join((d + '\n') for d in sorted_domains))

    # Create the cache directory, if it does not exist
    args.directory.mkdir(exist_ok=True)

    resolver = Resolver(
        cache_directory=args.directory,
        time_sleep=args.time_sleep,
        use_google=args.use_google,
        no_ssl=args.no_ssl,
    )

    # Fill the cache
    random.shuffle(domains)  # Do not be predictable
    for domain in domains:
        # Treat SRV records in a special way, to restrict the requested record type
        resolving_types = DNS_SRV_TYPES if '._tcp.' in domain or '._udp.' in domain else DNS_TYPES
        for rtype in resolving_types:
            # Do not resolve PTR for normal domains
            if rtype != 'PTR':
                resolver.resolve_in_cache(domain, rtype)

    # Resolve with well-known prefixes
    if args.prefixes:
        domains_with_prefixes = list(
            '{}.{}'.format(p, d)
            for p, d in itertools.product(WELLKNOWN_PREFIXES, domains))
        random.shuffle(domains_with_prefixes)  # Do not be predictable
        for domain in domains_with_prefixes:
            resolving_types = DNS_SRV_TYPES if '._tcp.' in domain or '._udp.' in domain else DNS_TYPES
            for rtype in resolving_types:
                if rtype != 'PTR':
                    resolver.resolve_in_cache(domain, rtype)

    # Load the cache
    resolver.load_cache(if_dirty=True)

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
            with args.file.open(mode='w') as fout:
                fout.write(''.join((d + '\n') for d in sorted_domains))

    # Produce the output
    if args.output:
        with args.output.open(mode='w') as fout:
            for line in resolver.dump_records(hide_dnssec=args.hide_dnssec):
                fout.write(line + '\n')

    if args.stdout or not args.output:
        for line in resolver.dump_records(hide_dnssec=args.hide_dnssec):
            print(line)

    # Merge all cache files together
    if args.merge_cache:
        resolver.merge_cache_files()


if __name__ == '__main__':
    main()
