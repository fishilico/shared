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
"""Analyze a network capture file using Scapy and produce a network map

Perform some analysis on a .pcap (and .pcapng) file with Scapy:
https://scapy.net/

In order to capture network traffic, it is possible to use:
* sudo tcpdump -w my_capture.pcap
* tshark -w my_capture.pcapng
* Wireshark

For example, to monitor network control protocols without recording common TCP
traffic (HTTP, HTTPS, SSH), the following command can be used:

    tshark -ni any -w my_capture.pcap -f 'not tcp port 80 and not tcp port 443 and not tcp port 22'

@author: Nicolas Iooss
@license: MIT
"""
import argparse
import binascii
import collections
import itertools
import ipaddress
import json
import logging
import os.path
import re
import socket
import subprocess
import sys

from scapy.all import ARP, BOOTP, CookedLinux, DHCP, DNS, Dot1Q, Dot3, Ether, \
    ICMPv6ND_NA, ICMPv6ND_RA, IP, IPv6, NBTDatagram, PcapReader, Raw, STP, UDP
from scapy.all import conf as scapy_conf

try:
    from scapy.layers.tls.all import TLS_Ext_ServerName
    HAVE_SCAPY_TLS = True
except ImportError:
    # TLS support has been introduced in scapy 2.4.0
    HAVE_SCAPY_TLS = False


# pylint: disable=invalid-name
logger = logging.getLogger(__name__)


GRAPH_COLORS = {
    'hwmanuf': 'cyan',
    'hwaddr': 'lightblue',
    'ipaddr': '#eeeeee',
    'publicipaddr': 'orange',
    'ipnet': 'green',
}


def unicode_ip_addr(ip_address):
    """Python 2 requires unicode IP addresses for ipaddress.* functions"""
    return ip_address.decode('ascii') if sys.version_info < (3,) else ip_address


def ip_sort_key(ip_address):
    """Get a sort key for an IPv4 or IPv6 address"""
    if ':' in ip_address:
        # IPv6
        return b'6' + socket.inet_pton(socket.AF_INET6, ip_address)
    # IPv4
    return b'4' + socket.inet_aton(ip_address)


def canonical_ipv4_address(ip_addr):
    """Return the IPv4 address in a canonical format"""
    return socket.inet_ntoa(socket.inet_aton(ip_addr))


def canonical_ipv6_address_with_version(ip_addr):
    """Return the IPv6 address in a canonical format"""
    ip_addr = socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, ip_addr))
    # V4MAPPED addresses in hybrid notation
    m = re.match(r'^::ffff:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$', ip_addr, re.I)
    if m is not None:
        return 4, m.group(1)
    return 6, ip_addr


def canonical_ip_address(ip_addr):
    """Return the canonical format of an IPv4 or IPv6 address"""
    if ':' in ip_addr:
        return canonical_ipv6_address_with_version(ip_addr)[1]
    return canonical_ipv4_address(ip_addr)


def is_public_ip_address(ip_addr):
    """Is the given IP address from a public range (not private nor local nor multicast)"""
    if ip_addr.startswith('10.'):  # 10.0.0.0/8
        return False
    if ip_addr.startswith('192.168.'):  # 192.168.0.0/16
        return False
    if re.match(r'^172\.(1[6789]|2[0123456789]|3[01])\.', ip_addr):  # 172.16.0.0/12
        return False
    if ip_addr.startswith('127.'):  # 127.0.0.0/8
        return False
    if ip_addr.startswith('169.254.'):  # 169.254.0.0/16
        return False
    if ip_addr.startswith('fe80::'):  # fe80::/16
        return False
    if re.match(r'^f[cd][0-9a-f][0-9a-f]:', ip_addr, re.I):  # fc00::/7
        return False
    return True


def get_mac_manuf_couple(mac_addr):
    """Get the manufacturer short and long names from a MAC address"""
    manufacturer = scapy_conf.manufdb._get_manuf_couple(mac_addr)  # pylint: disable=protected-access
    if manufacturer and manufacturer[0] != mac_addr:
        assert len(manufacturer) >= 2
        return manufacturer
    # Special MAC addresses
    mac_addr = mac_addr.lower()
    if mac_addr.startswith('01:00:5e:'):
        return ('IPv4mcast', 'IPv4 multicast')
    if mac_addr.startswith('33:33:'):
        return ('IPv6mcast', 'IPv6 multicast')
    if mac_addr == 'ff:ff:ff:ff:ff:ff':
        return ('broadcast', 'broadcast')
    # Manufacturer not found
    return None


def get_mac_manuf_desc(mac_addr, default='?'):
    """Get a string describing the manufacturer"""
    manufacturer = get_mac_manuf_couple(mac_addr)
    if not manufacturer:
        return default
    return manufacturer[1] or manufacturer[0]


def graphviz_records(records):
    """Escape record label according to https://www.graphviz.org/doc/info/shapes.html#record"""
    return ' | '.join(
        r.replace('\\', '\\\\').replace('{', '\\{').replace('}', '\\}').replace('<', '\\<').replace('>', '\\>')
        for r in records)


class Graph(object):
    """Graph of node and directed edges"""
    def __init__(self):
        self.nodes = {}
        self.edges = {}
        # IP network node -> ipaddress object
        self.ip_networks = {}
        self.already_added_ipaddr_nodes = set()

    def add_node(self, node_type, base_key, value):
        """Add a node to the graph and return a unique ID to it"""
        full_key = '{}_{}'.format(node_type, base_key)
        if full_key not in self.nodes:
            if value is None:
                value = base_key
            self.nodes[full_key] = (node_type, value)
        elif value is not None and self.nodes[full_key] != (node_type, value):
            logger.warning("Graph node %r has two values: %r and %r",
                           full_key, self.nodes[full_key], (node_type, value))
        return full_key

    def add_edge(self, node1, node2, label):
        """Add an edge to the graph"""
        if (node1, node2) not in self.edges:
            self.edges[(node1, node2)] = label
        elif self.edges[(node1, node2)] != label:
            logger.warning("Graph label (%s,%s) has two labels: %r and %r",
                           node1, node2, self.edges[(node1, node2)], label)

    def add_hw_manuf(self, manufacturer):
        """Add an hardware manufacturer"""
        return self.add_node('hwmanuf', manufacturer, manufacturer)

    def add_hw_addr(self, hw_addr, description):
        """Add an hardware address"""
        return self.add_node('hwaddr', hw_addr, description)

    def add_ip_addr(self, ip_addr, label=None):
        """Add an IP address"""
        node_type = 'publicipaddr' if is_public_ip_address(ip_addr) else 'ipaddr'
        ip_addr_node = self.add_node(node_type, ip_addr, label)
        # Add the node to a network, if it is a new one
        if ip_addr_node not in self.already_added_ipaddr_nodes:
            self.already_added_ipaddr_nodes.add(ip_addr_node)
            # Find the possible networks of the given address
            addr_obj = ipaddress.ip_address(unicode_ip_addr(ip_addr))
            possible_nets = [(node, obj) for node, obj in self.ip_networks.items() if addr_obj in obj]
            if possible_nets:
                possible_nets.sort(key=lambda x: x[1].prefixlen)
                self.add_edge(possible_nets[-1][0], ip_addr_node, 'member-net')
                # Add edges between subnets
                for idx in range(len(possible_nets) - 1):
                    self.add_edge(possible_nets[idx][0], possible_nets[idx + 1][0], 'subnet')
        return ip_addr_node

    def add_ip_network(self, net_obj, description):
        """Add an IP network"""
        net_node = self.add_node('ipnet', net_obj.with_prefixlen, description)
        if net_node not in self.ip_networks:
            # Record the IP network for IP address edges
            self.ip_networks[net_node] = net_obj
        return net_node

    def dump_dot(self, stream):
        """Produce a graph in dot format to the given stream"""
        stream.write('digraph {\n')
        stream.write('    overlap=prism;\n')
        stream.write('    rankdir=LR;\n')
        stream.write('    node [shape=record,style=filled];\n')

        # Dump nodes
        for key, type_value in sorted(self.nodes.items()):
            node_type, value = type_value
            color = GRAPH_COLORS.get(node_type)
            if any(ord(c) < 32 for c in value):
                # Escape values
                value = repr(value)
            value = value.replace('\\', '\\\\').replace('"', '\\"')
            stream.write('    "{}" [label="{}"'.format(key, value))
            if color is not None:
                stream.write(',fillcolor="{}"'.format(color))
            stream.write('];\n')

        # Dump edges
        for key, edge_label in sorted(self.edges.items()):
            if edge_label in ('member-net', 'subnet'):
                # Reverse the rank for ip-subnet link
                stream.write('    "{0[1]}" -> "{0[0]}" [dir="back"];\n'.format(key))
            else:
                stream.write('    "{0[0]}" -> "{0[1]}";\n'.format(key))
        stream.write('}\n')


class HwAddrDatabase(object):
    """Database of hardware addresses (ethernet MAC address, for Media Access Control)"""
    IGNORED_IP_ADDRESSES = frozenset(('0.0.0.0', '255.255.255.255', '::'))

    def __init__(self):
        # IP addresses seen for the given MAC address
        self.ip_for_hw = {}
        self.known_ip_addresses = set(self.IGNORED_IP_ADDRESSES)
        # MAC addresses of bridges
        self.bridges = set()
        # DHCP names associated with MAC addresses
        self.names_for_hw = {}

    @staticmethod
    def is_ignored(addr):
        """Ignore some addresses"""
        if addr == '00:00:00:00:00:00':
            return True
        return False

    def add_ip_addr(self, ip_version, ip_addr, hw_addr, description, silent=False):
        """Add an IP address-MAC address relationship"""
        if self.is_ignored(hw_addr):
            return
        if ip_addr in self.known_ip_addresses:
            return
        # Canonicalize the ip address
        if ip_version == 4:
            new_ip_addr = canonical_ipv4_address(ip_addr)
        elif ip_version == 6:
            new_ip_version, new_ip_addr = canonical_ipv6_address_with_version(ip_addr)
            if new_ip_version == 4:
                # The version changed, because it was an V4MAPPED address
                ip_version = new_ip_version
                ip_addr = new_ip_addr
        else:
            raise RuntimeError("Invalid IP version {}".format(ip_version))
        if new_ip_addr != ip_addr:
            logger.warning("Tried adding a non-canonical IPv%d address %r -> %r (from %s)",
                           ip_version, ip_addr, new_ip_addr, description)
            self.known_ip_addresses.add(ip_addr)
            ip_addr = new_ip_addr
            if ip_addr in self.known_ip_addresses:
                return
        if not silent:
            logger.info("Found IPv%d address %s for %s (%s) from %s",
                        ip_version, ip_addr, hw_addr,
                        get_mac_manuf_desc(hw_addr), description)
        if hw_addr not in self.ip_for_hw:
            self.ip_for_hw[hw_addr] = set()
        self.ip_for_hw[hw_addr].add(ip_addr)
        self.known_ip_addresses.add(ip_addr)

    def add_ipv4(self, ip_addr, hw_addr, description, silent=False):
        """Add an IPv4-MAC address relationship"""
        self.add_ip_addr(4, ip_addr, hw_addr, description, silent=silent)

    def add_ipv6(self, ip_addr, hw_addr, description, silent=False):
        """Add an IPv6-MAC address relationship"""
        self.add_ip_addr(6, ip_addr, hw_addr, description, silent=silent)

    def add_bridge(self, addr):
        """Define a hardware address as Layer-2 bridge or switch"""
        if self.is_ignored(addr):
            return
        if addr not in self.bridges:
            logger.info("Found a potential bridge with address %s (%s)", addr, get_mac_manuf_desc(addr))
            self.bridges.add(addr)

    def add_name(self, addr, name, description):
        """Add a name from a DHCP request"""
        if addr not in self.names_for_hw:
            self.names_for_hw[addr] = set()
        if name not in self.names_for_hw[addr]:
            logger.info("Adding name for %s: %r (%s)", addr, name, description)
            self.names_for_hw[addr].add(name)

    def remove_multicast_addresses(self):
        """Remove multicast hardware addresses from the database"""
        keys_to_remove = set()
        for hw_addr, ips in self.ip_for_hw.items():
            if hw_addr.startswith('01:00:5e:'):  # IPv4 multicast, 224.0.0.0/4 (until 239.255.255.255)
                for ip in list(ips):
                    if 224 <= int(ip.split('.', 1)[0]) <= 239:
                        logger.debug("Removing IPv4 multicast address %s (%s)", ip, hw_addr)
                        ips.remove(ip)
            if hw_addr.startswith('33:33:'):  # IPv6 multicast, ff00::/12
                for ip in list(ips):
                    if re.match(r'^ff0[0-9a-f]:', ip, re.I):
                        logger.debug("Removing IPv6 multicast address %s (%s)", ip, hw_addr)
                        ips.remove(ip)
            if not ips:
                keys_to_remove.add(hw_addr)
        for hw_addr in keys_to_remove:
            del self.ip_for_hw[hw_addr]

    def to_dict(self):
        """Export the data as an exportable dict"""
        result = {
            hwaddr: collections.OrderedDict((
                ('ip', sorted(ips, key=ip_sort_key)),
            ))
            for hwaddr, ips in self.ip_for_hw.items()
        }
        for hwaddr, names in sorted(self.names_for_hw.items()):
            if hwaddr not in result:
                result[hwaddr] = collections.OrderedDict()
            result[hwaddr]['names'] = sorted(names)
        for hwaddr in self.bridges:
            if hwaddr not in result:
                result[hwaddr] = collections.OrderedDict()
            result[hwaddr]['is_bridge'] = True

        # Record the manufacturer too, when it is known
        for hwaddr, result_data in result.items():
            manufacturer = get_mac_manuf_couple(hwaddr)
            if manufacturer is not None:
                result_data['manuf'] = manufacturer[0]
                if manufacturer[1] != manufacturer[0]:
                    # Put the long name if it is different from the short one
                    result_data['manufacturer'] = manufacturer[1]
        return collections.OrderedDict(sorted(result.items()))

    def load_dict(self, data):
        """Load previosly-exported data into this object"""
        for hw_addr, hw_data in data.items():
            if hw_data.get('is_bridge'):
                self.bridges.add(hw_addr)
            ip_addrs = hw_data.get('ip')
            if ip_addrs:
                if hw_addr not in self.ip_for_hw:
                    self.ip_for_hw[hw_addr] = set()
                for ip_addr in ip_addrs:
                    if ip_addr in self.known_ip_addresses:
                        continue
                    new_ip_addr = canonical_ip_address(ip_addr)
                    if new_ip_addr != ip_addr:
                        logger.warning("Tried loading a non-canonical IP address %r -> %r",
                                       ip_addr, new_ip_addr)
                        self.known_ip_addresses.add(ip_addr)
                        ip_addr = new_ip_addr
                        if ip_addr in self.known_ip_addresses:
                            return
                    self.ip_for_hw[hw_addr].add(ip_addr)
                    self.known_ip_addresses.add(ip_addr)
            names = hw_data.get('names')
            if names:
                if hw_addr not in self.names_for_hw:
                    self.names_for_hw[hw_addr] = set()
                self.names_for_hw[hw_addr].update(names)

    def populate_graph(self, graph):
        """Populate the given graph with information"""
        dict_data = self.to_dict()
        for hw_addr, hw_data in dict_data.items():
            desc_fields = [hw_addr]
            if hw_data.get('is_bridge'):
                desc_fields.append('bridge')
            manuf = hw_data.get('manufacturer') or hw_data.get('manuf')
            if manuf:
                desc_fields.append(manuf)
            for name in hw_data.get('names', []):
                desc_fields.append('Name: {}'.format(name))
            hw_addr_node = graph.add_hw_addr(hw_addr, graphviz_records(desc_fields))
            # if manuf:
            #     manuf_node = graph.add_hw_manuf(manuf)
            #     graph.add_edge(manuf_node, hw_addr_node, 'manufacturer')
            for ip_addr in hw_data.get('ip', []):
                ip_addr_node = graph.add_ip_addr(ip_addr)
                graph.add_edge(hw_addr_node, ip_addr_node, 'network interface')


class IpAddrDatabase(object):
    """Database of IP addresses, with associated names and roles"""
    def __init__(self):
        # dict of options for each address: IP -> option kind -> set of values
        self.addr_opts = {}
        self.canonical_cache = {}

    def add_option(self, ip_addr, kind, value, silent=False):
        """Add an option to the given IP address"""
        if ip_addr not in self.addr_opts:
            new_ip_addr = self.canonical_cache.get(ip_addr)
            if new_ip_addr is None:
                new_ip_addr = canonical_ip_address(ip_addr)
                if new_ip_addr != ip_addr:
                    if '::ffff:' + new_ip_addr != ip_addr:
                        # Only warns about non-V4MAPPED addresses
                        logger.warning("Tried adding a non-canonical IP address %r -> %r", ip_addr, new_ip_addr)
                    self.canonical_cache[ip_addr] = new_ip_addr
            ip_addr = new_ip_addr
            if ip_addr not in self.addr_opts:
                self.addr_opts[ip_addr] = {}
        addr_options = self.addr_opts[ip_addr]
        if kind not in addr_options:
            addr_options[kind] = set()
        if value not in addr_options[kind]:
            # Add values which are prefix for other values, before they are
            # removed in the post-processing pass, in order to quicken things.
            if any(v.startswith(value) for v in addr_options[kind]):
                logger.debug("Adding %s for %s even though an existing value shares a prefix: %r",
                             kind, ip_addr, value)
            elif not silent:
                logger.info("Adding %s for %s: %r", kind, ip_addr, value)
            addr_options[kind].add(value)

    def add_name(self, ip_addr, name):
        """Add a domain name"""
        self.add_option(ip_addr, 'name', name.strip('.'))

    def add_role(self, ip_addr, role):
        """Add a role to an IP address"""
        self.add_option(ip_addr, 'role', role)

    def post_processing(self):
        """Perform some post-processing operations on the data"""
        for opts in self.addr_opts.values():
            for kind, values in opts.items():
                # Sort the values
                sorted_values = sorted(values)
                if kind == 'role' and len(values) > 1:
                    # Remove roles which are less precise
                    for tested_idx in range(len(sorted_values) - 1):
                        tested_val = sorted_values[tested_idx]
                        for compared_idx in range(tested_idx + 1, len(sorted_values)):
                            if sorted_values[compared_idx].startswith(tested_val):
                                values.remove(tested_val)
                                break

    def to_dict(self):
        """Export the data as an exportable dict"""
        result = [
            (ip_addr, collections.OrderedDict((
                (kind, sorted(values)) for kind, values in sorted(opts.items())
            )))
            for ip_addr, opts in self.addr_opts.items()
        ]
        result.sort(key=lambda x: ip_sort_key(x[0]))
        return collections.OrderedDict(result)

    def load_dict(self, data):
        """Load previosly-exported data into this object"""
        for ip_addr, options in data.items():
            for kind, values in options.items():
                for value in values:
                    self.add_option(ip_addr, kind, value, silent=True)

    def populate_graph(self, graph):
        """Populate the given graph with information"""
        dict_data = self.to_dict()
        for ip_addr, options in dict_data.items():
            # Build a Graphviz record node
            records = [ip_addr]
            for kind, values in options.items():
                for val in values:
                    records.append("{}: {}".format(kind, val))
            graph.add_ip_addr(ip_addr, graphviz_records(records))


class IpNetworkDatabase(object):
    """Database of IP network segments (subnets)"""
    def __init__(self):
        # CIDR (Classless Inter-Domain Routing) -> ipaddress network object
        self.ipv4_networks = {}
        self.ipv6_networks = {}
        # CIDR -> name
        self.network_names = {}

    def add_network(self, address, name=None, silent=False):
        """Add an IP network"""
        net_obj = ipaddress.ip_network(unicode_ip_addr(address))
        net_cidr = net_obj.with_prefixlen
        if net_obj.version == 4:
            networks = self.ipv4_networks
        elif net_obj.version == 6:
            networks = self.ipv6_networks
        else:
            raise NotImplementedError("Unable to add IPv{} network {}".format(net_obj.version, address))
        if net_cidr not in networks:
            if not silent:
                logger.info("Adding network %s (%s)", net_cidr, net_obj.with_netmask)
            networks[net_cidr] = net_obj
        if name and not self.network_names.get(net_cidr):
            if not silent:
                logger.info("Adding network name %r for %s", name, net_cidr)
            self.network_names[net_cidr] = name

    def to_dict(self):
        """Export the data as an exportable dict"""
        sorted_ipv4_nets = sorted(
            self.ipv4_networks.items(),
            key=lambda x: (x[1].network_address.packed, x[1].prefixlen))
        sorted_ipv6_nets = sorted(
            self.ipv6_networks.items(),
            key=lambda x: (x[1].network_address.packed, x[1].prefixlen))
        result = collections.OrderedDict()
        for net_cidr, _ in itertools.chain(sorted_ipv4_nets, sorted_ipv6_nets):
            result[net_cidr] = self.network_names.get(net_cidr, '')
        return result

    def load_dict(self, data):
        """Load previosly-exported data into this object"""
        for net_cidr, name in data.items():
            self.add_network(net_cidr, name, silent=True)

    def populate_graph(self, graph):
        """Populate the given graph with information"""
        for net_cidr, net_obj in itertools.chain(self.ipv4_networks.items(), self.ipv6_networks.items()):
            name = self.network_names.get(net_cidr, '')
            desc = '{} ({})'.format(net_cidr, name) if name else net_cidr
            graph.add_ip_network(net_obj, desc)


class AnalysisContext(object):
    """Container of several databases"""
    def __init__(self):
        self.hwaddrdb = HwAddrDatabase()
        self.ipaddrdb = IpAddrDatabase()
        self.ipnetdb = IpNetworkDatabase()
        self.seen_eth_dec_mop_dna_rc = False
        self.seen_eth_lldp = False
        self.seen_eth_fortinet = False
        self.seen_eth_802_11 = False

    def post_processing(self, add_local_networks=False):
        """Perform some post-processing operations on the data"""
        self.ipaddrdb.post_processing()

        if add_local_networks:
            # If there are IPv4 link local addresses, show them in the network
            if any(ip_addr.startswith('169.254.') for ip_addr in self.hwaddrdb.known_ip_addresses):
                self.ipnetdb.add_network('169.254.0.0/16', 'IPv4 link-local')
            # If there are IPv6 link local addresses, show them in the network
            if any(ip_addr.startswith('fe80::') for ip_addr in self.hwaddrdb.known_ip_addresses):
                self.ipnetdb.add_network('fe80::/64', 'IPv6 link-local')

            # If there are IPv4 multicast addresses, show then in the network
            if any(re.match(r'^2(2[456789]|3[0123456789])\.', ip_addr) for ip_addr in self.hwaddrdb.known_ip_addresses):
                self.ipnetdb.add_network('224.0.0.0/4', 'IPv4 multicast')
            # If there are IPv6 multicast addresses, show then in the network
            if any(re.match(r'^ff0[0-9a-f]:', ip_addr, re.I) for ip_addr in self.hwaddrdb.known_ip_addresses):
                self.ipnetdb.add_network('ff00::/12', 'IPv6 multicast')

    def to_dict(self):
        """Export the data as an exportable dict"""
        return collections.OrderedDict((
            ('hwaddrdb', self.hwaddrdb.to_dict()),
            ('ipaddrdb', self.ipaddrdb.to_dict()),
            ('ipnetdb', self.ipnetdb.to_dict()),
        ))

    def load_dict(self, data):
        """Load previosly-exported data into this object"""
        hwaddr_data = data.get('hwaddrdb')
        if hwaddr_data:
            self.hwaddrdb.load_dict(hwaddr_data)
        ipaddr_data = data.get('ipaddrdb')
        if ipaddr_data:
            self.ipaddrdb.load_dict(ipaddr_data)
        ipnet_data = data.get('ipnetdb')
        if ipnet_data:
            self.ipnetdb.load_dict(ipnet_data)

    def populate_graph(self, graph):
        """Populate the given graph with information"""
        self.ipnetdb.populate_graph(graph)
        self.ipaddrdb.populate_graph(graph)
        self.hwaddrdb.populate_graph(graph)

    def remove_multicast_addresses(self):
        """Remove multicast addresses from the databases"""
        self.hwaddrdb.remove_multicast_addresses()
        if '224.0.0.0/4' in self.ipnetdb.ipv4_networks:
            del self.ipnetdb.ipv4_networks['224.0.0.0/4']
        if 'ff00::/12' in self.ipnetdb.ipv6_networks:
            del self.ipnetdb.ipv6_networks['ff00::/12']

    def remove_non_hw_ip(self):
        """Remove IP addresses which were not seen in any local connections

        These IP addresses may have come from DNS resolutions)
        """
        for ip_addr, ip_options in list(self.ipaddrdb.addr_opts.items()):
            if ip_addr not in self.hwaddrdb.known_ip_addresses or ip_addr in self.hwaddrdb.IGNORED_IP_ADDRESSES:
                logger.debug("Removing unconnected IP address %s (%r)", ip_addr, ip_options)
                del self.ipaddrdb.addr_opts[ip_addr]

    def filter_by_known_networks(self):
        """Only keep IP addresses that belong to a network"""
        known_networks = set(self.ipnetdb.ipv4_networks.values())
        known_networks.update(self.ipnetdb.ipv6_networks.values())
        logger.info("Filtering IP addresses to only include those which belong to %d known networks",
                    len(known_networks))
        for ips in self.hwaddrdb.ip_for_hw.values():
            for ip_addr in list(ips):
                ip_addr_obj = ipaddress.ip_address(unicode_ip_addr(ip_addr))
                if all(ip_addr_obj not in net_obj for net_obj in known_networks):
                    ips.remove(ip_addr)
                    try:
                        self.hwaddrdb.known_ip_addresses.remove(ip_addr)
                    except KeyError:
                        pass

        self.remove_non_hw_ip()

    def simplify_for_graph(self):
        """Simplify the data before graphing it"""
        logger.debug("Simplifying the data... (use --all to skip this)")
        self.remove_non_hw_ip()

    def analyze_read_packet(self, pkt):
        """Analyze a single packet read from a capture file"""
        if isinstance(pkt, Ether):
            # Base captured packets is Ethernet II
            self.analyze_ether_packet(pkt)
            return
        if isinstance(pkt, Dot3):  # IEEE 802.3 Ethernet
            if pkt.haslayer(STP):
                # IEEE 802.1D Spanning Tree Protocol
                self.hwaddrdb.add_bridge(pkt[STP].bridgemac)
                return
            # logger.debug("Skipping IEEE 802.3 packet %r", pkt)
            return
        if isinstance(pkt, CookedLinux):  # Captured from any interface
            self.analyze_ether_packet(pkt, is_cookedlinux=True)
            return
        logger.warning("Unknown packet type %r", pkt)

    def analyze_ether_packet(self, ethpkt, is_cookedlinux=False):
        """Analyze an Ethernet packet or a Cooked Linux one"""
        base_pkt = ethpkt
        if is_cookedlinux:
            pkt_type = base_pkt.proto
            hex_hw_src = binascii.hexlify(base_pkt.src).decode('ascii')
            hw_src = ':'.join(hex_hw_src[i:i + 2] for i in range(0, 12, 2))
            hw_dst = None
        else:
            pkt_type = base_pkt.type
            hw_src = ethpkt.src
            hw_dst = ethpkt.dst

        while pkt_type == 0x8100:  # IEEE 802.1Q VLAN (Virtual Local Area Network)
            base_pkt = base_pkt[1]
            assert isinstance(base_pkt, Dot1Q)
            pkt_type = base_pkt.type

        if pkt_type == 4:  # 802.2 LLC (Logical Link Control)
            # This packet may contain an STP payload which indicates a bridge,
            # but it is not parsed well by scapy.
            # In order to get it: configure a bridge on a Linux machine and
            # capture traffic on interface "any".
            pass
        elif pkt_type == 8:  # LLC (Logical Link Control)
            pass
        elif pkt_type == 0x800:  # IPv4
            ippkt = base_pkt[1]
            assert isinstance(ippkt, IP)
            self.hwaddrdb.add_ipv4(ippkt.src, hw_src, 'IPv4 packet source')
            if hw_dst is not None:
                self.hwaddrdb.add_ipv4(ippkt.dst, hw_dst, 'IPv4 packet destination')
            self.analyze_ipv4_packet(ippkt)
        elif pkt_type == 0x806:  # ARP
            arppkt = base_pkt[1]
            assert isinstance(arppkt, ARP)
            if arppkt.op == 1:  # ARP who-has?
                self.hwaddrdb.add_ipv4(arppkt.psrc, arppkt.hwsrc, 'ARP who-has? source')
            elif arppkt.op == 2:  # ARP is-at
                self.hwaddrdb.add_ipv4(arppkt.psrc, arppkt.hwsrc, 'ARP is-at source')
                self.hwaddrdb.add_ipv4(arppkt.pdst, arppkt.hwdst, 'ARP is-at destination')
            else:
                logger.warning("Unknown ARP packet %r", arppkt)
        elif pkt_type == 0x6002:  # DNA_RC, for Decnet Maintenance Operation Protocol (MOP) Remote Console (RC)
            if hw_dst != 'ab:00:00:02:00:00':
                logger.warning("Unexpected Ethernet destination for DEC MOP DNA_RC packet: %r", ethpkt)
            elif not self.seen_eth_dec_mop_dna_rc:
                logger.info(
                    "DEC MOP DNA_RC packet found in capture. This may signal a Cisco router (%r)",
                    ethpkt)
                self.seen_eth_dec_mop_dna_rc = True
        elif pkt_type == 0x8035:  # Reverse ARP (https://tools.ietf.org/html/rfc903)
            rarppkt = base_pkt[1]
            assert isinstance(rarppkt, Raw)
            # Ignore RARP request for IPv4 address:
            # - hardware type: Ethernet (1)
            # - protocol type: IPv4 (0x0800)
            # - hardware size: 6
            # - protocol size: 4
            # - opcode: reverse request (3) or reverse response (4)
            if rarppkt.load.startswith(b'\x00\x01\x08\x00\x06\x04\x00\x03'):
                pass
            else:
                logger.warning("Unknown RARP packet: %r", ethpkt)
        elif pkt_type == 0x86dd:  # IPv6
            ippkt = base_pkt[1]
            assert isinstance(ippkt, IPv6)
            self.hwaddrdb.add_ipv6(ippkt.src, hw_src, 'IPv6 packet source')
            if hw_dst is not None:
                self.hwaddrdb.add_ipv6(ippkt.dst, hw_dst, 'IPv6 packet destination')
            self.analyze_ipv6_packet(ippkt)
        elif pkt_type == 0x888e:  # EAPOL (IEEE 802.1X)
            pass
        elif pkt_type == 0x88cc:  # LLDP
            # Scapy does not understand LLDP, but Wireshark does.
            # These packets may given VLAN IDs and network names.
            if not self.seen_eth_lldp:
                logger.info(
                    "LLDP found in packet capture. This may give useful information about the network (%r)",
                    ethpkt)
                # logger.debug("Skipping LLDP packet %r", ethpkt)
                self.seen_eth_lldp = True
        elif pkt_type in (0x8890, 0x8891, 0x8893):
            # Fortinet hardware uses these special ethernet types
            # https://help.fortinet.com/fos50hlp/56/Content/FortiOS/fortigate-high-availability/HA_failoverHeartbeat.htm
            if not self.seen_eth_fortinet:
                logger.info(
                    "Fortinet Heartbit found in capture. This may give useful information about the network (%r)",
                    ethpkt)
                self.seen_eth_fortinet = True
        elif pkt_type == 0x890d:  # IEEE 802.11 data encapsulation (WiFi)
            # The source MAC address is probably a WiFi access point on a wired network
            self.hwaddrdb.add_bridge(hw_src)
            if not self.seen_eth_802_11:
                logger.info(
                    "Encapsulated 802.11 data found, probably emitted by a WiFi access point (%r)",
                    ethpkt)
                self.seen_eth_802_11 = True
        elif pkt_type == 0x9000:  # Configuration Test Protocol (loopback), from a Cisco switch
            self.hwaddrdb.add_bridge(hw_src)
        else:
            logger.warning("Unknown Ethernet packet type %#x: %r", pkt_type, ethpkt)

    def analyze_ipv4_packet(self, ippkt):
        """Analyze an IPv4 packet"""
        bootp_client_addr = None
        if ippkt.haslayer(BOOTP):
            bootppkt = ippkt[BOOTP]
            hex_mac_addr = binascii.hexlify(bootppkt.chaddr).decode('ascii')
            if any(c != '0' for c in hex_mac_addr[12:]):
                logger.warning("Ignoring BOOTP packet with invalid MAC address %r", hex_mac_addr)
            elif any(c != '0' for c in hex_mac_addr[:12]):
                # The MAC address is not empty
                mac_addr = ':'.join(hex_mac_addr[i:i + 2] for i in range(0, 12, 2))

                bootp_client_addr = bootppkt.ciaddr
                if bootp_client_addr == '0.0.0.0':
                    bootp_client_addr = None
                else:
                    self.hwaddrdb.add_ipv4(bootp_client_addr, mac_addr, 'BOOTP packet from {}'.format(ippkt.src))

                # Find out the client hostname
                if bootppkt.haslayer(DHCP):
                    dhcppkt = ippkt[DHCP]
                    for opt in dhcppkt.options:
                        if opt[0] in ('hostname', 'client_FQDN'):
                            for opt_val in opt[1:]:
                                if opt[0] == 'client_FQDN' and opt_val == b'\x00\xff\xff':
                                    # Ignore client FQDN with "flags=0, A-RR result=\xff, PTR-R result=\xff"
                                    continue
                                name = opt_val.decode('utf-8', 'replace').strip('\0')
                                self.hwaddrdb.add_name(mac_addr, name,
                                                       'DHCP option {} from {}'.format(opt[0], mac_addr))

        if ippkt.haslayer(DHCP):
            dhcppkt = ippkt[DHCP]
            # Collect options to describe the DHCP server
            dhcp_options = {
                'domains': set(),
                'router': None,
                'subnet_mask': None,
                'hostname': None,
                'client_FQDN': None,
            }
            for opt in dhcppkt.options:
                if opt in ('pad', 'end'):
                    continue
                if opt[0] == 'domain':
                    for opt_val in opt[1:]:
                        dhcp_options['domains'].add(opt_val.decode('utf8', 'replace').strip('\0'))
                if opt[0] == 'subnet_mask':
                    for opt_val in opt[1:]:
                        if dhcp_options['subnet_mask'] is not None:
                            logger.warning("Duplicate DHCP subnet mask option: %r and %r",
                                           dhcp_options['subnet_mask'], opt_val)
                        else:
                            dhcp_options['subnet_mask'] = opt_val
                if opt[0] == 'router':
                    for opt_val in opt[1:]:
                        if dhcp_options['router'] is not None:
                            logger.warning("Duplicate DHCP router option: %r and %r",
                                           dhcp_options['router'], opt_val)
                        else:
                            dhcp_options['router'] = opt_val
                if opt[0] == 'hostname':
                    for opt_val in opt[1:]:
                        if dhcp_options['hostname'] is not None:
                            logger.warning("Duplicate DHCP hostname option: %r and %r",
                                           dhcp_options['hostname'], opt_val)
                        else:
                            dhcp_options['hostname'] = opt_val.decode('utf-8', 'replace')
                if opt[0] == 'client_FQDN':
                    for opt_val in opt[1:]:
                        if opt_val == b'\x00\xff\xff':
                            continue
                        if dhcp_options['client_FQDN'] is not None:
                            logger.warning("Duplicate DHCP client_FQDN option: %r and %r",
                                           dhcp_options['client_FQDN'], opt_val)
                        else:
                            dhcp_options['client_FQDN'] = opt_val.decode('utf-8', 'replace').strip('\0')

            if bootp_client_addr is not None:
                if dhcp_options['hostname'] is not None:
                    self.ipaddrdb.add_option(bootp_client_addr, 'DHCP_hostname', dhcp_options['hostname'])
                if dhcp_options['client_FQDN'] is not None:
                    self.ipaddrdb.add_option(bootp_client_addr, 'DHCP_client_FQDN', dhcp_options['client_FQDN'])
                # Add the network for the client
                if dhcp_options['subnet_mask'] is not None:
                    iface_addr = '{}/{}'.format(bootp_client_addr, dhcp_options['subnet_mask'])
                    ip_iface = ipaddress.ip_interface(unicode_ip_addr(iface_addr))
                    self.ipnetdb.add_network(ip_iface.network.with_prefixlen)

            dhcp_desc = ''
            if dhcp_options['router'] is not None:
                dhcp_desc += ' for network {}'.format(dhcp_options['router'])
                if dhcp_options['subnet_mask'] is not None:
                    dhcp_desc += '/{}'.format(dhcp_options['subnet_mask'])
                    iface_addr = '{}/{}'.format(dhcp_options['router'], dhcp_options['subnet_mask'])
                    ip_iface = ipaddress.ip_interface(unicode_ip_addr(iface_addr))
                    self.ipnetdb.add_network(ip_iface.network.with_prefixlen)
            if dhcp_options['domains']:
                dhcp_desc += ' (DNS {})'.format(', '.join(sorted(dhcp_options['domains'])))
            for opt in dhcppkt.options:
                if opt[0] == 'server_id':
                    for opt_addr in opt[1:]:
                        self.ipaddrdb.add_role(opt_addr, 'DHCP server' + dhcp_desc)
                if opt[0] == 'name_server':
                    for opt_addr in opt[1:]:
                        self.ipaddrdb.add_role(opt_addr, 'DNS server in DHCP' + dhcp_desc)
                if opt[0] == 'router':
                    for opt_addr in opt[1:]:
                        self.ipaddrdb.add_role(opt_addr, 'gateway in DHCP' + dhcp_desc)

        self.analyze_generic_ip_packet(ippkt)

    def analyze_ipv6_packet(self, ippkt):
        """Analyze an IPv6 packet"""
        if ippkt.haslayer(ICMPv6ND_NA):  # Neighbor Advertisement (of Neighbor Discovery Protocol)
            # N.B. Neighbor Solicitation used IPv6 fields for the emitter
            ndpkt = ippkt[ICMPv6ND_NA]
            try:
                na_mac_address = ndpkt.lladdr
            except AttributeError:
                # Some Neighbor Advertisement packets do not carry a link-layer address
                pass
            else:
                self.hwaddrdb.add_ipv6(ndpkt.tgt, na_mac_address, 'Neighbor Advertisement')

        if ippkt.haslayer(ICMPv6ND_RA):  # Router Advertisement (of Neighbor Discovery Protocol)
            rapkt = ippkt[ICMPv6ND_RA]
            ra_options = {
                'src_ll_addr': None,
                'prefix_ip': None,
            }
            option = rapkt.payload
            while option:
                opt_type = option.__class__.__name__
                if opt_type == 'ICMPv6NDOptSrcLLAddr':
                    if ra_options['src_ll_addr'] is not None:
                        logger.warning("Duplicate NDP RA source LLAddress option: %r and %r",
                                       ra_options['src_ll_addr'], option.lladdr)
                    else:
                        ra_options['src_ll_addr'] = option.lladdr
                if opt_type == 'ICMPv6NDOptPrefixInfo':
                    if ra_options['prefix_ip'] is not None:
                        logger.warning("Duplicate NDP RA prefix info option: %r and %r",
                                       ra_options['prefix_ip'], option)
                    else:
                        iface_obj = ipaddress.ip_interface(unicode_ip_addr(
                            '{}/{}'.format(option.prefix, option.prefixlen)))
                        ra_options['prefix_ip'] = iface_obj.network.with_prefixlen
                        self.ipnetdb.add_network(ra_options['prefix_ip'])
                option = option.payload

            ra_desc = ''
            if ra_options['prefix_ip'] is not None:
                ra_desc += ' for network {}'.format(ra_options['prefix_ip'])
            if ra_options['src_ll_addr'] is not None:
                ra_desc += ' from {}'.format(ra_options['src_ll_addr'])

            self.ipaddrdb.add_role(ippkt.src, 'Advertiser of IPv6 Router' + ra_desc)

            option = rapkt.payload
            while option:
                opt_type = option.__class__.__name__
                if opt_type == 'ICMPv6NDOptPrefixInfo':
                    self.ipaddrdb.add_role(option.prefix, 'IPv6 Router' + ra_desc)
                elif opt_type == 'ICMPv6NDOptRDNSS':
                    for opt_addr in option.dns:
                        self.ipaddrdb.add_role(opt_addr, 'DNS server in RA' + ra_desc)
                option = option.payload

        self.analyze_generic_ip_packet(ippkt)

    def analyze_generic_ip_packet(self, ippkt):
        """Analyze an IPv4 or IPv6 packet"""
        if ippkt.haslayer(UDP):
            udppkt = ippkt[UDP]
            if udppkt.haslayer(NBTDatagram):  # Microsoft NetBIOS (UDP 138)
                nbtpkt = udppkt[NBTDatagram]
                nbt_srcip = nbtpkt.SourceIP
                nbt_srcname = nbtpkt.SourceName.decode('utf-8', 'replace').strip()
                self.ipaddrdb.add_option(nbt_srcip, 'NetBIOS_name', nbt_srcname)

        if ippkt.haslayer(DNS):  # DNS and MDNS
            dnspkt = ippkt[DNS]
            if dnspkt.an is not None:
                for answer_idx in range(dnspkt.ancount):
                    try:
                        dns_record = dnspkt.an[answer_idx]
                    except IndexError:
                        # This occurs when the DNS packet has been truncated by Wireshark
                        pass
                    else:
                        self.analyze_dns_record(dns_record)

        if HAVE_SCAPY_TLS and ippkt.haslayer(TLS_Ext_ServerName):  # TLS Server Name Indication Extension
            tls_sni = ippkt[TLS_Ext_ServerName]
            for tls_sni_name_obj in tls_sni.servernames:
                if tls_sni_name_obj.nametype != 0:
                    logger.warning("Unexpected TLS SNI name type in %r", tls_sni_name_obj)
                    continue
                tls_sni_name = tls_sni_name_obj.servername.decode('utf-8', 'replace').strip()
                self.ipaddrdb.add_name(ippkt.dst, tls_sni_name)

    def analyze_dns_record(self, dns_record):
        """Analyze a packet with a DNS record"""
        dns_type = dns_record.get_field('type').i2repr(dns_record, dns_record.type)
        rrname = dns_record.rrname.decode('utf-8', errors='replace')
        if dns_type == 'A':
            self.ipaddrdb.add_name(dns_record.rdata, rrname)
            return
        if dns_type == 'AAAA':
            self.ipaddrdb.add_name(dns_record.rdata, rrname)
            return
        if dns_type == 'PTR':
            if rrname.endswith(('._tcp.local.', '._udp.local.')):
                return
            match = re.match(r'^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\.in-addr\.arpa\.$', rrname, re.I)
            if match:
                ip_addr = '.'.join(match.groups()[::-1])
                self.ipaddrdb.add_name(ip_addr, dns_record.rdata.decode('utf-8'))
                return
            match = re.match(r'^' + (r'([0-9a-f])\.' * 32) + r'ip6\.arpa\.$', rrname, re.I)
            if match:
                bin_ipv6 = binascii.unhexlify(''.join(match.groups()[::-1]))
                ip_addr = socket.inet_ntop(socket.AF_INET6, bin_ipv6)
                self.ipaddrdb.add_name(ip_addr, dns_record.rdata.decode('utf-8'))
                return
        if dns_type in ('DNSKEY', 'DS', 'RRSIG'):  # Ignore DNSSEC records
            return
        if dns_type in ('TKEY', 'TSIG'):  # Ignore DNS transfers and updates
            return
        if dns_type in ('NS', 'SOA'):  # Ignore DNS infrastructure records
            return
        if dns_type in ('CNAME', 'HINFO', 'MX', 'SRV', 'SSHFP', 'TXT'):
            return

        logger.warning("Unknown DNS packet type %r for %r: %r", dns_type, rrname, dns_record)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Map a network from a capture file")
    parser.add_argument('file', metavar="PCAPFILE", nargs='*', type=str,
                        help="network capture files to parse")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-i', '--input', metavar='IMPORT_JSON_FILE', action='append', type=str,
                        help="input file from a previous output, in JSON format")
    parser.add_argument('-o', '--output', metavar='EXPORT_JSON_FILE', type=str,
                        help="output file in JSON format")
    parser.add_argument('-n', '--known-networks', action='store_true',
                        help="only include IP addresses which belong to known networks (in JSON and graph)")
    parser.add_argument('-L', '--add-local-networks', action='store_true',
                        help="automatically add local IP networks (in JSON and graph)")
    parser.add_argument('-A', '--all', action='store_true',
                        help="graph all the collected data without any filter")
    parser.add_argument('-M', '--with-multicast', action='store_true',
                        help="show IPv4 and IPv6 multicast address in the graph")
    parser.add_argument('-g', '--graph', metavar='GRAPH_FILE', type=str,
                        help="produce a graph of the collected data")
    parser.add_argument('-G', '--graph-format', type=str,
                        help="format of the graph (dot, png, svg, etc.)")
    parser.add_argument('-t', '--tree', action='store_true',
                        help="output the graph as a flat tree")
    args = parser.parse_args(argv)

    if not args.file and not args.input:
        parser.error("a network capture file or a JSON import is required")

    if args.graph:
        graph_format = args.graph_format
        if not graph_format:
            fileext = os.path.splitext(args.graph)[1].lower()
            # Use DOT by default
            graph_format = fileext.lstrip('.') or 'dot'
        if graph_format not in ('dot', 'fig', 'jpg', 'jpeg', 'json', 'pdf', 'png', 'ps', 'svg', 'svgz', 'xdot'):
            parser.error("unknown graph format {}".format(graph_format))

    logging.basicConfig(format='[%(levelname)s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    ctx = AnalysisContext()

    if args.input:
        for jsonpath in args.input:
            logger.debug("Loading %s", jsonpath)
            with open(jsonpath, 'r') as fjson:
                ctx.load_dict(json.load(fjson))

    for filepath in args.file:
        logger.debug("Reading %s", filepath)
        for pkt in PcapReader(filepath):  # pylint: disable=no-value-for-parameter
            ctx.analyze_read_packet(pkt)

    ctx.post_processing(add_local_networks=args.add_local_networks)
    if args.known_networks:
        ctx.filter_by_known_networks()

    ctx_export = ctx.to_dict()
    if args.output:
        logger.debug("Writing %s", args.output)
        with open(args.output, 'w') as fout:
            json.dump(ctx_export, fout, indent=2)
            fout.write('\n')

    if args.graph:
        # Remove some information from the databases, in order to simplify the graph
        if not args.all:
            if not args.with_multicast:
                ctx.remove_multicast_addresses()
            ctx.simplify_for_graph()

        graph = Graph()
        ctx.populate_graph(graph)
        if graph_format == 'dot':
            logger.debug("Drawing %s (xdot can render it)", args.graph)
            with open(args.graph, 'w') as fdot:
                graph.dump_dot(fdot)
        else:
            # Run graphviz
            if args.tree:
                cmdline = ['dot', '-T' + graph_format, '-o' + args.graph]
            else:
                cmdline = ['sfdp', '-Goverlap=prism', '-T' + graph_format, '-o' + args.graph]
            logger.info("Running %s", ' '.join(cmdline))
            proc = subprocess.Popen(cmdline, stdin=subprocess.PIPE, universal_newlines=True)
            graph.dump_dot(proc.stdin)
            proc.stdin.close()
            exitcode = proc.wait()
            if exitcode:
                logger.error("sfdp (Graphviz) failed: %d", exitcode)
                return exitcode

    if not args.output and not args.graph:
        print(json.dumps(ctx_export, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
