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
"""Enumerate a DNS domain using NSEC records (Next Secure)

Some domains where it works:
* example.org
* example.com
* dnssec-tools.org
* internetsociety.org.
"""
import argparse
import errno
import logging
import re
import subprocess
import sys


logger = logging.getLogger(__name__)


class NSecRecord(object):
    """NSEC record"""
    def __init__(self, name, next_name, record_types):
        self.name = name
        self.next_name = next_name
        self.record_types = record_types

    @classmethod
    def from_dns_entry(cls, line):
        """Parse a DNS entry

        For example:
            example.org. 3599 IN NSEC www.example.org. A NS SOA TXT AAAA RRSIG NSEC DNSKEY
        """
        fields = line.strip().split(None)
        assert fields[2] == 'IN', "Unknown DNS class {}".format(fields[2])
        assert fields[3] == 'NSEC', "Not a DNS NSEC record: type {}".format(fields[3])
        return cls(
            name=fields[0],
            next_name=fields[4],
            record_types=fields[5:],
        )

    @classmethod
    def from_host_output(cls, line):
        """Parse the result of command "host"

        For example:
            $ host -t NSEC example.org
            example.org has NSEC record www.example.org. A NS SOA TXT AAAA RRSIG NSEC DNSKEY
        """
        if re.match(r'.* has no NSEC record', line.strip()):
            return None
        matches = re.match(r'^([A-Za-z0-9._-]+) has NSEC record ([ A-Za-z0-9._-]+)$', line.strip())
        assert matches, "Invalid host output {}".format(repr(line))
        name, result = matches.groups()
        if not name.endswith('.'):
            name += '.'
        fields = result.split()
        return cls(
            name=name,
            next_name=fields[0],
            record_types=fields[1:],
        )

    @classmethod
    def query_dns_with_host(cls, domain):
        """Execute a host command to get a NSEC record"""
        cmdline = ['host', '-t', 'NSEC', domain]
        logger.debug("Running %r", ' '.join(cmdline))
        cmd_output = subprocess.check_output(cmdline)
        if cmd_output:
            return cls.from_host_output(cmd_output.decode('utf-8'))
        return None

    @classmethod
    def query_dns(cls, domain, use_host=False):
        """Query the DNS server for a NSEC record for the specified domain"""
        if use_host:
            # Force using host
            return cls.query_dns_with_host(domain)

        # Try using drill or dig
        for prgm in ('drill', 'dig'):
            cmdline = [prgm, domain, 'NSEC']
            logger.debug("Running %r", ' '.join(cmdline))
            try:
                cmd_output = subprocess.check_output(cmdline)
            except OSError as exc:
                # Ignore if the program is not installed
                if exc.errno != errno.ENOENT:
                    raise
            else:
                for line in cmd_output.splitlines():
                    if line.strip() and not line.startswith(b';') and b'NSEC' in line:
                        return cls.from_dns_entry(line.decode('utf-8'))
                return None

        # As last resort, use "host"
        return cls.query_dns_with_host(domain)


def enumerate_with_nsec(domain, use_host=False):
    """Enumerate the content of a zone using NSEC entries"""
    known_entries = set()
    while domain not in known_entries:
        nsec = NSecRecord.query_dns(domain, use_host=use_host)
        if nsec is None:
            logger.error("No NSEC record found for %r", domain)
            return False
        print("{} ({})".format(nsec.name, ', '.join(nsec.record_types)))
        known_entries.add(nsec.name)
        domain = nsec.next_name
    print("[NSEC loop closed with {}]".format(domain))
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description="Enumerate DNS records using NSEC")
    parser.add_argument('domains', metavar="DOMAIN", nargs='+', type=str,
                        help="domain name from which the enumeration starts")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-H', '--use-host', action='store_true',
                        help="use command 'host'")
    args = parser.parse_args(argv)

    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    for domain in args.domains:
        if not enumerate_with_nsec(domain, use_host=args.use_host):
            return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
