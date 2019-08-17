#!/usr/bin/env python3
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
"""This program show how it is possible to run an UDP server with multihoming.

The main issue is to reply to incoming requests with the right source address,
when several ones are available.  This is done by using recvmsg/sendmsg
functions instead of recvfrom/sendto which only control the remote address.
This use-case is called "multihoming".

This program has been insipred by OpenVPN source code (src/openvpn/socket.c)

@author: Nicolas Iooss
@license: MIT
"""
import argparse
import logging
import os
import socket
import struct
import sys


logger = logging.getLogger(__name__)

# Check feature availability (need python>=3.3)
if not hasattr(socket.socket, 'recvmsg'):
    raise NotImplementedError("socket.recvmsg() not found (need Python >= 3.3)")

# Define some system-specific constants
if sys.platform.startswith('linux'):
    if not hasattr(socket, 'IP_PKTINFO'):
        socket.IP_PKTINFO = 8
    if not hasattr(socket, 'IPV6_RECVPKTINFO'):
        socket.IPV6_RECVPKTINFO = 49
    if not hasattr(socket, 'IPV6_PKTINFO'):
        socket.IPV6_PKTINFO = 50
    if not hasattr(socket, 'SO_BINDTODEVICE'):
        socket.SO_BINDTODEVICE = 25
elif os.name == 'nt':
    if not hasattr(socket, 'IP_RECVDSTADDR'):
        socket.IP_RECVDSTADDR = 25
    if not hasattr(socket, 'IPV6_RECVDSTADDR'):
        socket.IPV6_RECVDSTADDR = 25
else:
    raise Exception("Unsupported system")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Simple multihomed UDP server")
    parser.add_argument('-p', '--port', type=int, default=4242,
                        help="UDP port to be used (default: 4242)")
    parser.add_argument('-w', '--wait', action='store_true',
                        help="wait for connections instead of creating one")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-4', '--ipv4', action='store_true',
                       help="create an IPv4-only socket")
    group.add_argument('-6', '--ipv6', action='store_true',
                       help="create an IPv6-only socket")

    args = parser.parse_args(argv)

    # Compute local variables
    af = socket.AF_INET if args.ipv4 else socket.AF_INET6
    localaddr = '127.0.0.1' if args.ipv4 else '::1'
    anyaddr = '0.0.0.0' if args.ipv4 else '::'
    port = args.port if args.port > 0 else 4242

    # Create and configure socket for multihoming
    skserver = socket.socket(af, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    if not args.ipv6:
        if hasattr(socket, 'IP_PKTINFO'):
            skserver.setsockopt(socket.SOL_IP, socket.IP_PKTINFO, 1)
        elif hasattr(socket, 'IP_RECVDSTADDR'):
            skserver.setsockopt(socket.IPPROTO_IP, socket.IP_RECVDSTADDR, 1)
    if not args.ipv4:
        if hasattr(socket, 'IPV6_RECVPKTINFO'):
            skserver.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        elif hasattr(socket, 'IPV6_RECVDSTADDR'):
            skserver.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVDSTADDR, 1)
    if not args.ipv4:
        skserver.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, args.ipv6)

    # Listen
    if args.wait:
        listenaddr = anyaddr
    elif args.ipv6 or args.ipv4:
        listenaddr = localaddr
    else:
        # To protect dual-stack listen, bind the socket to the loopback interface
        listenaddr = anyaddr
        try:
            skserver.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'lo\0')
        except PermissionError as exc:
            logger.warn("Unable to bind to loopback interface: {}".format(exc))

    ainfos = socket.getaddrinfo(listenaddr, port, af, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    skserver.bind(ainfos[0][4])

    if args.wait:
        logger.info("Waiting for a connection on UDP port {}.".format(port))
    else:
        # Create a client socket, which uses IPv4-in-IPv6 if enabled
        clientaf = socket.AF_INET if not args.ipv6 else socket.AF_INET6
        clientdstaddr = '127.0.0.1' if not args.ipv6 else '::1'
        skclient = socket.socket(clientaf, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        skclient.sendto(b'Hello, world!', (clientdstaddr, port))

    # Receive an incoming packet
    (msg, ancdata, _, clientaddrport) = skserver.recvmsg(1024, socket.CMSG_SPACE(100))
    assert args.wait or msg == b'Hello, world!'  # Check the socket channel
    dst_addr = None
    ifindex = None
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_IP and hasattr(socket, 'IP_PKTINFO') and cmsg_type == socket.IP_PKTINFO:
            # struct in_pktinfo { int ipi_ifindex; struct in_addr ipi_spec_dst, ipi_addr; };
            assert len(cmsg_data) == 12
            dst_addr = socket.inet_ntop(socket.AF_INET, cmsg_data[4:8])
            ifindex = struct.unpack('I', cmsg_data[:4])[0]
        elif cmsg_level == socket.IPPROTO_IPV6 and hasattr(socket, 'IPV6_PKTINFO') and cmsg_type == socket.IPV6_PKTINFO:
            # struct in6_pktinfo { struct in6_addr ipi6_addr; int ipi_ifindex; };
            assert len(cmsg_data) == 20
            dst_addr = socket.inet_ntop(socket.AF_INET6, cmsg_data[:16])
            ifindex = struct.unpack('I', cmsg_data[16:20])[0]
        else:
            logger.warning("Unknown anciliary data: {}, {}, {}".format(cmsg_level, cmsg_type, cmsg_data))
        # TODO: decode IP_RECVDSTADDR/IPV6_RECVDSTADDR
    text = "Received UDP packet from {0[0]} port {0[1]}".format(clientaddrport)
    if dst_addr is not None:
        text += " to {} port {} interface {}".format(dst_addr, port, ifindex)
    logger.info(text)

    # Send back a reply with the same ancillary data
    skserver.sendmsg([b'Bye!\n'], ancdata, 0, clientaddrport)

    skserver.close()
    if not args.wait:
        skclient.close()
    return 0


if __name__ == '__main__':
    logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)
    sys.exit(main())
