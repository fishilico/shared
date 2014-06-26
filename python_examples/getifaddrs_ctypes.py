#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2014 Nicolas Iooss
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
"""Enumerate the available network interface addresses using ctypes

@author: Nicolas Iooss
@license: MIT
"""
# pylint: disable=invalid-name,missing-docstring,superfluous-parens
# pylint: disable=too-few-public-methods
import argparse
import array
import ctypes
import ctypes.util
import fcntl
import socket
import sys

# /usr/include/linux/if.h
IFNAMSIZ = 16
IFF_NOARP = 0x80

# /usr/include/linux/sockios.h
SIOCGIFNAME = 0x8910
SIOCGIFINDEX = 0x8933


def str_family(family, _static_known_af={}):
    """Get a string representation of an address family"""
    # pylint: disable=dangerous-default-value
    if len(_static_known_af) == 0:
        for constant in socket.__all__:
            if constant.startswith('AF_'):
                _static_known_af[getattr(socket, constant)] = constant
    if family in _static_known_af:
        return _static_known_af[family]
    else:
        return str(family)


class struct_sockaddr_storage(ctypes.Structure):
    _fields_ = [
        ('ss_family', ctypes.c_uint16),
        ('ss_data', ctypes.c_uint8 * 124)]


class struct_sockaddr_in(ctypes.Structure):
    _fields_ = [
        ('sin_family', ctypes.c_uint16),
        ('sin_port', ctypes.c_uint16),
        ('sin_addr', ctypes.c_uint8 * 4)]

    def str_addr(self):
        assert self.sin_family == socket.AF_INET
        assert self.sin_port == 0
        addr = array.array('B', self.sin_addr)
        return socket.inet_ntop(socket.AF_INET, addr.tostring())


class struct_sockaddr_in6(ctypes.Structure):
    _fields_ = [
        ('sin6_family', ctypes.c_uint16),
        ('sin6_port', ctypes.c_uint16),
        ('sin6_flowinfo', ctypes.c_uint32),
        ('sin6_addr', ctypes.c_uint8 * 16),
        ('sin6_scope_id', ctypes.c_uint32)]

    def str_addr(self):
        assert self.sin6_family == socket.AF_INET6
        assert self.sin6_port == 0
        addr = array.array('B', self.sin6_addr)
        text = socket.inet_ntop(socket.AF_INET6, addr.tostring())
        if self.sin6_scope_id:
            text += '%{:d}'.format(self.sin6_scope_id)
        return text


class struct_sockaddr_ll(ctypes.Structure):
    _fields_ = [
        ('sll_family', ctypes.c_uint16),
        ('sll_protocol', ctypes.c_uint16),
        ('sll_ifindex', ctypes.c_uint32),
        ('sll_hatype', ctypes.c_uint16),  # ARPHRD_...
        ('sll_pkttype', ctypes.c_uint8),  # PACKET_...
        ('sll_halen', ctypes.c_uint8),
        ('sll_addr', ctypes.c_uint8 * 8)]

    def str_addr(self):
        assert self.sll_family == socket.AF_PACKET
        assert self.sll_protocol == 0
        assert self.sll_pkttype == 0
        assert self.sll_halen <= len(self.sll_addr)
        addr = self.sll_addr[:self.sll_halen]
        return ':'.join('{:02x}'.format(x) for x in addr)


class struct_sockaddr(ctypes.Union):
    _fields_ = [
        ('sa_storage', struct_sockaddr_storage),
        ('sa_in', struct_sockaddr_in),
        ('sa_in6', struct_sockaddr_in6),
        ('sa_ll', struct_sockaddr_ll)]

    def str_addr(self):
        family = self.sa_storage.ss_family
        if family == socket.AF_INET:
            return self.sa_in.str_addr()
        elif family == socket.AF_INET6:
            return self.sa_in6.str_addr()
        if family == socket.AF_PACKET:
            return self.sa_ll.str_addr()
        else:
            raise NotImplementedError("address family {} not yet implemented"
                                      .format(str_family(family)))


class union_ifa_ifu(ctypes.Union):
    _fields_ = [
        ('ifu_broadaddr', ctypes.POINTER(struct_sockaddr)),
        ('ifu_dstaddr', ctypes.POINTER(struct_sockaddr))]


class struct_ifaddrs(ctypes.Structure):
    pass


struct_ifaddrs._fields_ = [  # pylint: disable=protected-access
    ('ifa_next', ctypes.POINTER(struct_ifaddrs)),
    ('ifa_name', ctypes.c_char_p),
    ('ifa_flags', ctypes.c_uint),
    ('ifa_addr', ctypes.POINTER(struct_sockaddr)),
    ('ifa_netmask', ctypes.POINTER(struct_sockaddr)),
    ('ifa_ifu', union_ifa_ifu),
    ('ifa_data', ctypes.c_void_p)]


class union_ifreq(ctypes.Union):
    _fields_ = [
        ('ifr_addr', struct_sockaddr),
        ('ifr_broadaddr', struct_sockaddr),
        ('ifr_netmask', struct_sockaddr),
        ('ifr_hwaddr', struct_sockaddr),
        ('ifr_flags', ctypes.c_uint16),
        ('ifr_ifindex', ctypes.c_int32),
        ('ifr_metric', ctypes.c_int32),
        ('ifr_mtu', ctypes.c_int32)]  # Some types are missing but useless here


class struct_ifreq(ctypes.Structure):
    _fields_ = [
        ('ifr_name', ctypes.c_char * IFNAMSIZ),
        ('u', union_ifreq)]


libc = ctypes.CDLL(ctypes.util.find_library('c'))
libc.getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(struct_ifaddrs))]
libc.freeifaddrs.argtypes = [ctypes.POINTER(struct_ifaddrs)]


def get_network_interfaces():
    """Get a generator of network interfaces"""
    ifa_list = ctypes.POINTER(struct_ifaddrs)()
    result = libc.getifaddrs(ctypes.pointer(ifa_list))
    if result == -1:
        raise OSError(ctypes.get_errno())
    try:
        ifa_item = ifa_list
        while ifa_item:
            ifa = ifa_item.contents
            yield ifa
            ifa_item = ifa.ifa_next
    finally:
        libc.freeifaddrs(ifa_list)


def get_ifindex_from_name(ifname):
    """Get the interface index associated to the given name"""
    sd = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
    ifr = struct_ifreq()
    ifr.ifr_name = ifname.encode('ascii')
    fcntl.ioctl(sd, SIOCGIFINDEX, ifr, True)
    sd.close()
    return int(ifr.u.ifr_ifindex)


def get_ifname_from_index(ifindex):
    """Get the interface name associated to the given index"""
    sd = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
    ifr = struct_ifreq()
    ifr.u.ifr_ifindex = ifindex
    fcntl.ioctl(sd, SIOCGIFNAME, ifr, True)
    sd.close()
    return ifr.ifr_name.decode('ascii')


def family_addresses_sortkey(family_address):
    """Give a sort key for a list of (family, address) tuples"""
    af_order = [socket.AF_PACKET, socket.AF_INET, socket.AF_INET6]
    family, addr = family_address
    return (
        af_order.index(family) if family in af_order else len(af_order),
        str_family(family),
        addr)


def main(argv=None):
    """Program entry point"""
    parser = argparse.ArgumentParser(
        description="Enumerate network interface addresses")
    parser.add_argument('-4', '--ipv4', action='store_true',
                        help="show IPv4 address family (AF_INET)")
    parser.add_argument('-6', '--ipv6', action='store_true',
                        help="show IPv6 address family (AF_INET6)")
    parser.add_argument('-p', '--packet', action='store_true',
                        help="show link address family (AF_PACKET)")
    args = parser.parse_args(argv)

    displayed_families = []
    if args.ipv4:
        displayed_families.append(socket.AF_INET)
    if args.ipv6:
        displayed_families.append(socket.AF_INET6)
    if args.packet:
        displayed_families.append(socket.AF_PACKET)

    if_addrs = {}
    if_indexes = {}
    for ifa in get_network_interfaces():
        ifname = ifa.ifa_name.decode('ascii')
        if ifname not in if_addrs:
            # Get interface index and check that the name is right
            ifindex = get_ifindex_from_name(ifname)
            ifname2 = get_ifname_from_index(ifindex)
            # When ifname = "eth0:0", ifname2 = "eth0"
            assert ifname.startswith(ifname2)
            if_addrs[ifname] = []
            if_indexes[ifname] = ifindex
        if not ifa.ifa_addr:
            # If no ARP, it's normal not to have a L2 address
            assert ifa.ifa_flags & IFF_NOARP
            continue
        sa = ifa.ifa_addr.contents
        family = sa.sa_storage.ss_family
        if not displayed_families or family in displayed_families:
            if_addrs[ifname].append((family, sa.str_addr()))
        if family == socket.AF_PACKET:
            assert if_indexes[ifname] == sa.sa_ll.sll_ifindex

    sorted_ifidx = sorted(if_indexes.items(), key=lambda x: (x[1], x[0]))
    for ifname, ifindex in sorted_ifidx:
        af_addrs = sorted(if_addrs[ifname], key=family_addresses_sortkey)
        if not af_addrs:
            continue
        print("{}{}:".format(
            ifname, " (interface {})".format(ifindex) if ifindex else ""))
        for family, address in af_addrs:
            print("  {}: {}".format(str_family(family), address))
    return 0


if __name__ == '__main__':
    sys.exit(main())
