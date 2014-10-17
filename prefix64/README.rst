Prefix64
========

This project is a proof of concept for a server which can communicate using
every IPv6 address in a /64 prefix. This can be used to make web virtual hosts
using several IPv6 addresses instead of multiplexing one and requiring an HTTP
Host header or a TLS SNI extension header from clients.

This project provides a simple PHP script which displays some IPv6 addresses
and generates a new random IPv6 address in the /64 prefix used by the server.


Setup
-----

You need:

- a Linux server
- a root account on this server
- a web server like Apache or Nginx running on this server
- a /64 IPv6 prefix to this server

Once you have that, each time your provider receives a packet to an address in
your prefix, the packet is transmitted to your server, but by default it will
ignore it or transmit it to somewhere else because its destination address is
not bound to any interface. To tell your server that the packet is for itself,
you need to configure something similar to transparent proxy
(https://www.kernel.org/doc/Documentation/networking/tproxy.txt).

Here are the commands you need to run as root  (replace ``eth0`` with your
external interface)::

    ip6tables -t mangle -A PREROUTING -i eth0 -p tcp -m tcp --dport 80 -j MARK --set-mark 64
    ip6tables -t mangle -A PREROUTING -i eth0 -p ipv6-icmp -j MARK --set-mark 64
    ip -6 route add local default dev lo table 64
    ip -6 rule add fwmark 64 lookup 64

Then configure your web server to listen on ``[::]:80``.
Here is what I use with Nginx::

    server {
        listen [::]:80 default_server ipv6only=on;

        root /var/www/prefix64;
        index index.php index.html index.htm;

        server_name prefix64.example.com;

        access_log /var/log/nginx/access_prefix64.log;
        error_log /var/log/nginx/error_prefix64.log;

        location / {
            try_files $uri $uri/ /index.php;
        }

        location ~ ^(.+?\.php)(/.*)?$ {
            try_files $1 =404;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$1;
            fastcgi_param PATH_INFO $2;
            fastcgi_pass unix:/var/run/php5-fpm.sock;
        }
    }

Copy ``index.php`` into ``/var/www/prefix64`` and go to your literal IPv6
address in a browser. For example, if your prefix is ``2001:db8::/64``, try
http://[2001:db8:0:0:fedc:ba98:7654:3210]/.


Neighbor Discovery Protocol Proxy
---------------------------------

The above setup works fine when the routing configuration of the Internet routes
packets with destination addresses in the /64 range to the server.  Some
Internet providers only routes until the last router and then the router
sends a Neighbor Solicitation to retrieve the link-layer address associated to
the IPv6 address (this is the Neighbor Discovery Protocol, "NDP").  In such a
scenario, the server needs to reply with a Neighbor Advertisement message so
that the router sends the packets correctly.

Once the server is configured to answer NS with NA, the server can process
ICMPv6 echo request ("ping6"), as shown by ``tcpdump -ni eth0 ip6``::

    fe80::2ff:ffff:feff:fffd > ff02::1:ff57:cafe: ICMP6, neighbor solicitation, who has 2001:db8::be57:cafe, length 32
    fe80::200:00ff:fe00:0000 > fe80::2ff:ffff:feff:fffd: ICMP6, neighbor advertisement, tgt is 2001:db8::be57:cafe, length 32
    2001:db8::dead:beef > 2001:db8::be57:cafe: ICMP6, echo request, seq 1, length 64
    2001:db8::be57:cafe > 2001:db8::dead:beef: ICMP6, echo reply, seq 1, length 64

There are two ways to do such a configuration.  The first consists in using the
kernel IPv6 stack by configuring "IPv6 proxy neighbors".  This enables the
kernel to answer solicitation for specific addresses.  For example this
configures the kernel to answer soliciations for 2001:db8::be57:cafe::

    sysctl -w net.ipv6.conf.eth0.proxy_ndp=1
    ip neigh add proxy 2001:db8::be57:cafe dev eth0

The list of currently-configured neighbor proxies can be seen with::

    ip neigh show proxy

As Linux kernel does not support IP address ranges to be proxied, a daemon has
been implemented to answer solicitations for ranges, ``ndppd`` (NDP Proxy
Daemon): http://priv.nu/projects/ndppd/

This daemon is configured with file ``/etc/ndppd.conf``::

    proxy eth0 {
        rule 2001:db8::/64 {
        }
    }

Once the daemon is correctly configured and started, it handles the NDP messages
so that packets are routed to the server, which can then process them.
