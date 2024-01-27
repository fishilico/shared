#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# Copyright (c) 2023 Nicolas Iooss
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
"""Sniff DNS responses to detect issues

This is useful to detect applications, websites or services using out-dated
domain names.

Inspired by: https://twitter.com/ctbbpodcast/status/1739754236081037546?t=9_CPz2CJQOccz3K1xoYTzA&s=19
"""
import argparse
import datetime
import enum
import json
import subprocess
import sys
from typing import Any, Mapping, List, Tuple


@enum.unique
class DnsRdataTypes(enum.IntEnum):
    """Identifiers of DNS record data types"""

    NONE = 0
    A = 1
    NS = 2
    MD = 3
    MF = 4
    CNAME = 5
    SOA = 6
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12
    HINFO = 13
    MINFO = 14
    MX = 15
    TXT = 16
    RP = 17
    AFSDB = 18
    X25 = 19
    ISDN = 20
    RT = 21
    NSAP = 22
    NSAP_PTR = 23
    SIG = 24
    KEY = 25
    PX = 26
    GPOS = 27
    AAAA = 28
    LOC = 29
    NXT = 30
    SRV = 33
    NAPTR = 35
    KX = 36
    CERT = 37
    A6 = 38
    DNAME = 39
    OPT = 41
    APL = 42
    DS = 43
    SSHFP = 44
    IPSECKEY = 45
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    DHCID = 49
    NSEC3 = 50
    NSEC3PARAM = 51
    TLSA = 52
    SMIMEA = 53
    HIP = 55
    NINFO = 56
    RKEY = 57
    TALINK = 58
    CDS = 59
    CDNSKEY = 60
    OPENPGPKEY = 61
    CSYNC = 62
    ZONEMD = 63
    SVCB = 64
    HTTPS = 65
    SPF = 99
    UNSPEC = 103
    NID = 104
    L32 = 105
    L64 = 106
    LP = 107
    EUI48 = 108
    EUI64 = 109
    TKEY = 249
    TSIG = 250
    IXFR = 251
    AXFR = 252
    MAILB = 253
    MAILA = 254
    ANY = 255
    URI = 256
    CAA = 257
    AVC = 258
    DOA = 259
    TA = 32768
    DLV = 32769
    RESERVED_65534 = 65534


@enum.unique
class DnsRcodes(enum.IntEnum):
    """DNS response code, from https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1"""

    NOERR = 0  # No error condition
    FORMERR = 1  # Format error
    SERVFAIL = 2  # Server failure
    NXDOMAIN = 3  # Name Error
    NOTIMPL = 4  # Not Implemented
    REFUSED = 5


# Cache the last notifications, to not repeat them
notification_cache: List[Tuple[str, str]] = []


def notify(title: str, message: str) -> None:
    """Display a desktop notification on Linux, using
    https://wiki.archlinux.org/title/Desktop_notifications
    """
    global notification_cache
    try:
        previous_index = notification_cache.index((title, message))
    except ValueError:
        pass
    else:
        # Refresh the cache and do not display the notification, if the same one recently occured
        notification_cache.append(notification_cache.pop(previous_index))
        return

    if len(notification_cache) >= 10:
        notification_cache = notification_cache[1:]
    notification_cache.append((title, message))

    subprocess.check_output(
        ["notify-send", title, message, "--icon=dialog-warning", "--urgency=low", "--expire-time=3000"]
    )


def string_list_item(items: Mapping[str, Any], name: str) -> List[str]:
    """Return an item which could be absent, a string or a list of strings"""
    try:
        value = items[name]
    except KeyError:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return value
    raise NotImplementedError(f"Cannot extract {name!r} ({value!r}) from {items!r}")


def sniff_dns(all_rtypes: bool = False) -> None:
    """Sniff DNS responses to detect issues"""
    ignored_query_rtypes: Set[DnsRdataTypes] = (
        set()
        if all_rtypes
        else {DnsRdataTypes.AAAA, DnsRdataTypes.HTTPS, DnsRdataTypes.MX, DnsRdataTypes.PTR, DnsRdataTypes.SRV}
    )

    # Use ElasticSearch format to have line-by-line packet descriptions
    proc = subprocess.Popen(
        [
            "tshark",
            "--no-promiscuous-mode",
            "-lnqQ",
            "-iany",
            "-Tek",
            "-Jdns",
            "udp src port 53 or tcp src port 53",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
    )
    assert proc.stdout is not None  # For type-checking with mypy
    for captured_line in proc.stdout:
        fields = json.loads(captured_line)
        try:
            dns_fields = fields["layers"]["dns"]
        except KeyError:
            continue
        timestamp = datetime.datetime.fromtimestamp(int(fields["timestamp"]) / 1000.0)
        hms = timestamp.strftime("%H:%M:%S")
        try:
            dns_rcode = DnsRcodes(int(dns_fields["dns_dns_flags"], 0) & 0xF)
        except ValueError:
            print(f"Warning: invalid DNS response code in {dns_fields!r}")
            raise
        dns_count_queries = int(dns_fields["dns_dns_count_queries"])
        dns_query_name: str = dns_fields["dns_dns_qry_name"]
        try:
            dns_query_type = DnsRdataTypes(int(dns_fields["dns_dns_qry_type"]))
        except ValueError:
            print(f"Warning: invalid DNS type in query of {dns_fields!r}")
            raise
        dns_count_answers = int(dns_fields["dns_dns_count_answers"])
        dns_resp_names = string_list_item(dns_fields, "dns_dns_resp_name")
        dns_resp_cnames = string_list_item(dns_fields, "dns_dns_cname")
        dns_resp_types_str = string_list_item(dns_fields, "dns_dns_resp_type")
        try:
            dns_resp_types: List[DnsRdataTypes] = [DnsRdataTypes(int(t)) for t in dns_resp_types_str]
        except ValueError:
            print(f"Warning: invalid DNS type in response of {dns_fields!r}")
            raise

        if dns_count_queries != 1:
            print(f"Warning: unexpected dns_count_queries = {dns_count_queries!r} in {dns_fields!r}", file=sys.stderr)

        # Report domain names without answers.
        # As some records are expected to be often empty (MX, HTTPS...),
        # do not report them except when all_rtypes is set.
        if dns_count_answers == 0 and dns_query_type not in ignored_query_rtypes:
            if dns_resp_types and dns_resp_types[0] == DnsRdataTypes.NS:
                # When a non-recursive resolver answers, it gives the name server to contact in NS replies
                pass
            else:
                print(f"[{hms}] {dns_query_name!r} ({dns_query_type.name}) without answers ({dns_rcode.name})")
                notify("Broken DNS", f"{dns_query_name!r} ({dns_query_type.name}) without answers ({dns_rcode.name})")

        # Find broken CNAME records: the query resolved to a CNAME target which was not resolved.
        # When doing a AAAA request to a CNAME with only a target A record, there is no response and this is normal.
        # So ignore this situation except when all_rtypes is set.
        if dns_query_type not in ignored_query_rtypes:
            broken_cnames = sorted(set(dns_resp_cnames).difference(dns_resp_names))
            for target in broken_cnames:
                print(f"[{hms}] {dns_query_name!r} ({dns_query_type.name}) resolved to a broken CNAME {target!r} ({dns_rcode.name})")
                notify(
                    "Broken CNAME", f"{dns_query_name!r} ({dns_query_type.name}) resolved to a broken CNAME {target!r} ({dns_rcode.name})"
                )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sniff DNS responses to detect issues")
    parser.add_argument("-a", "--all-rtypes", help="show issues with all DNS record types")
    args = parser.parse_args()
    sniff_dns(all_rtypes=args.all_rtypes)
