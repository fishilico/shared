#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
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
"""
Reassemble TCP streams from a network capture file.

This can be used as a base to parse protocols based on TCP/IP.

Dependencies:

* Scapy (tested with Scapy 2.4.3)

Usage on Linux:

1. Capture traffic, for example with WireShark or tcpdump.
2. Filter the network capture in order to only include the TCP port of interest:

    tshark -r capture_from_wireshark.pcapng.gz -w clean_capture.pcap -Y 'tcp.port == 1234'

3. Run the analyzer:

    ./parse_tcpchannel.py clean_capture.pcap

@author Nicolas Iooss
@license: MIT
"""
import argparse
from contextlib import suppress
import logging

from scapy.all import PcapReader, Padding


# pylint: disable=invalid-name
logger = logging.getLogger(__name__)


def repr_0(value, basecolor=''):
    """Represent binary data by replacing \0 with a colored underscore"""
    return basecolor + repr(value).replace('\\x00', '\033[36m_\033[m' + basecolor) + '\033[m'


class TcpStream:
    """Hold information about a TCP stream"""

    def __init__(self, ipsrc, ipdst, tcpsrc, tcpdst):
        self.ipsrc = ipsrc
        self.ipdst = ipdst
        self.tcpsrc = tcpsrc
        self.tcpdst = tcpdst
        self.last_tcpseq_c2s = None
        self.last_tcpseq_s2c = None
        self.current_data_c2s = b''
        self.current_data_s2c = b''
        self.expected_tcpseq_c2s = None
        self.expected_tcpseq_s2c = None  # Server2Client may be fragmented
        self.future_paquets_s2c = []
        self.pkt_idx = 0

        logger.info("Initiating TCP conn to %s:%s", ipdst, tcpdst)

    def got_synack(self, seq_s2c, ack_c2s):
        """Got sequence numbers from a SYN+ACK packet"""
        if self.last_tcpseq_s2c is not None:
            logger.warning("Got a duplicated TCP SYN+ACK for %s:%d > %s:%d",
                           self.ipsrc, self.tcpsrc, self.ipdst, self.tcpdst)
        elif self.last_tcpseq_c2s is not None:
            # TCP Fast open
            if self.last_tcpseq_c2s + 1 == ack_c2s:
                logger.warning("Rejected TCP SYN+ACK with TCP Fast Open for %s:%d > %s:%d",
                               self.ipsrc, self.tcpsrc, self.ipdst, self.tcpdst)
            else:
                logger.warning(
                    "Got an unexpected TCP SYN+ACK with TCP Fast Open for %s:%d > %s:%d: %d + 1 != %d",
                    self.ipsrc, self.tcpsrc, self.ipdst, self.tcpdst, self.last_tcpseq_c2s, ack_c2s)

        self.last_tcpseq_c2s = ack_c2s
        self.last_tcpseq_s2c = seq_s2c
        self.expected_tcpseq_c2s = ack_c2s
        self.expected_tcpseq_s2c = seq_s2c + 1

    def add_payload(self, data, client_to_server, seq):
        """Got a new TCP packet, adding it to the internal buffers"""
        if client_to_server:
            if self.last_tcpseq_c2s == seq and self.expected_tcpseq_c2s != seq:
                # Ignore repeated packets
                return

            if self.current_data_s2c:  # Drop recv bytes when sending
                logger.warning("Ignoring %d recv bytes", len(self.current_data_s2c))
                self.current_data_s2c = b''

            self.last_tcpseq_c2s = seq
            # print("[>] %d + %d = %d" % (seq, len(data), seq + len(data))); data = b''
            data = self.process_packets(self.current_data_c2s + data, client_to_server)
            self.current_data_c2s = data
        else:
            if self.last_tcpseq_s2c == seq and self.expected_tcpseq_s2c != seq:
                # Ignore repeated packets
                return

            if self.current_data_c2s:  # Drop sent bytes when receiving
                logger.warning("Ignoring %d sent bytes", len(self.current_data_s2c))
                self.current_data_c2s = b''

            if self.expected_tcpseq_s2c != seq:
                logger.warning("Bad order of packets: %#x vs. %#x", self.expected_tcpseq_s2c, seq)
                if self.expected_tcpseq_s2c < seq:
                    # The packet is a future one... keep it
                    self.future_paquets_s2c.append((seq, data))
                    return

            self.last_tcpseq_s2c = seq
            self.expected_tcpseq_s2c = seq + len(data)
            # print("[TCP<] %#x + %d = %#x" % (seq, len(data), seq + len(data)))
            data = self.process_packets(self.current_data_s2c + data, client_to_server)
            self.current_data_s2c = data
            # Unstack stashed packets
            if self.future_paquets_s2c:
                unstashed_packet_idx = None
                for idx, pkt in enumerate(self.future_paquets_s2c):
                    if pkt[0] == self.expected_tcpseq_s2c:
                        unstashed_packet_idx = idx
                        break
                if unstashed_packet_idx is not None:
                    seq, new_data = self.future_paquets_s2c.pop(unstashed_packet_idx)
                    logger.warning("Found out-of-order now :) %#x, sending %d+%d=%d=%#x bytes",
                                   seq, len(data), len(new_data),
                                   len(data) + len(new_data),
                                   len(data) + len(new_data))
                    # The data is already in self.current_data_s2c
                    self.add_payload(new_data, client_to_server, seq)
                    return

    def process_packets(self, data, client_to_server):
        """Process parts of a packet and return the remaining (unparsed data)"""
        # By default, display the packet and return nothing
        print("[{}:{} {} {}:{}] {}".format(
            self.ipsrc, self.tcpsrc,
            '<>'[client_to_server],
            self.ipdst, self.tcpdst,
            repr_0(data)))
        return b''


def get_ip_layer(packet):
    """Return the IPv4 or IPv6 layer of a packet, if it exists. Otherwise None"""
    with suppress(IndexError):
        return packet['IP']
    with suppress(IndexError):
        return packet['IPv6']
    return None


def analyze_pcap_for_tcp(pcap_file):
    """Analyze a PCAP file with TCP communications"""
    tcp_streams = {}
    for packet in PcapReader(pcap_file):
        ippkt = get_ip_layer(packet)
        if ippkt is None or ippkt.proto != 6:  # TCP protocol is 6
            continue
        tcppkt = ippkt['TCP']

        # Gather packet metadata
        ipsrc = ippkt.src
        ipdst = ippkt.dst
        tcpsrc = tcppkt.sport
        tcpdst = tcppkt.dport

        # Match the packet with existing streams in tcp_streams
        client_to_server = None
        tcpip_tuple = (ipdst, ipsrc, tcpdst, tcpsrc)
        if tcpip_tuple in tcp_streams:
            client_to_server = False
            if tcppkt.flags.SA:  # SYN=2 + ACK=0x10
                tcp_streams[tcpip_tuple].got_synack(tcppkt.seq, tcppkt.ack)
        else:
            tcpip_tuple = (ipsrc, ipdst, tcpsrc, tcpdst)
            if tcpip_tuple in tcp_streams:
                client_to_server = True
            elif tcppkt.flags.S:  # SYN
                tcp_streams[tcpip_tuple] = TcpStream(ipsrc, ipdst, tcpsrc, tcpdst)
                client_to_server = True
            else:
                logger.debug("Ignoring non-SYN first TCP packet %r", tcpip_tuple)
                continue

        assert client_to_server is not None  # Ensure that the direction has been found

        # Ignore Ethernet padding that might slips into the TCP packet
        if isinstance(tcppkt.payload, Padding):
            continue

        payload_bytes = bytes(tcppkt.payload)
        if payload_bytes:
            tcp_streams[tcpip_tuple].add_payload(payload_bytes, client_to_server, tcppkt.seq)

    logger.debug("Analyzed %d TCP streams", len(tcp_streams))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Reassemble TCP streams from a network capture file")
    parser.add_argument('file', metavar="PCAPFILE", nargs='+', type=str,
                        help="network capture files to parse")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    args = parser.parse_args(argv)

    logging.basicConfig(format='[%(levelname)s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    for pcap_file_path in args.file:
        analyze_pcap_for_tcp(pcap_file_path)


if __name__ == '__main__':
    main()
