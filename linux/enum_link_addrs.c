/**
 * Gather the link addresses from all interfaces, using netlink route socket.
 *
 * The link address is also called "hardward address", "link-level address" and
 * can be found in getifaddrs results with family AF_PACKET.
 *
 * Documentation:
 * * libnetlink man page:
 *   http://man7.org/linux/man-pages/man3/libnetlink.3.html
 * * libnetlink implementation:
 *   http://git.kernel.org/cgit/linux/kernel/git/shemminger/iproute2.git/tree/lib/libnetlink.c
 * * glibc implementation of getifaddrs, using netlink:
 *   https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/ifaddrs.c;hb=HEAD
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <net/if_arp.h>

/* linetlink.h uses "inline", which is not ISO C */
#ifndef inline
#    define inline __inline__
#endif
#include <libnetlink.h>

/* libnetlink uses casts to char* to perform pointer arithmetic */
#pragma GCC diagnostic ignored "-Wcast-align"

static int print_linkaddr_filter(
    const struct sockaddr_nl *rth __attribute__ ((unused)),
    struct nlmsghdr *nlh,
    void *arg __attribute__ ((unused)))
{
    struct ifinfomsg *ifim = (struct ifinfomsg *)NLMSG_DATA(nlh);
    size_t rtasize = IFLA_PAYLOAD(nlh);
    struct rtattr *rta, *rta_name = NULL, *rta_addr = NULL;

    if (nlh->nlmsg_type != RTM_NEWLINK)
        return 0;

    /* Gather information about the link */
    for (rta = IFLA_RTA(ifim); RTA_OK(rta, rtasize); rta = RTA_NEXT(rta, rtasize)) {
        if (rta->rta_type == IFLA_IFNAME) {
            rta_name = rta;
        } else if (rta->rta_type == IFLA_ADDRESS) {
            rta_addr = rta;
        }
    }

    /* Display it */
    printf("%d: ", ifim->ifi_index);
    if (rta_name) {
        printf("%*s: ", (int)RTA_PAYLOAD(rta_name) - 1, (char *)RTA_DATA(rta_name));
    }
    if (rta_addr) {
        unsigned char *addr = RTA_DATA(rta_addr);
        size_t len = RTA_PAYLOAD(rta_addr), pos;
        for (pos = 0; pos < len; pos++) {
            if (pos)
                printf(":");
            printf("%02x", addr[pos]);
        }
    } else {
        printf("no address");
    }

    /* Types defined in /usr/include/net/if_arp.h */
    printf(", type %d", ifim->ifi_type);
    switch (ifim->ifi_type) {
        case ARPHRD_ETHER:
            printf(" (ethernet)");
            break;
        case ARPHRD_LOOPBACK:
            printf(" (loopback)");
            break;
    }
    printf("\n");
    return 0;
}

int main(void)
{
    struct rtnl_handle rth;
    struct rtnl_dump_filter_arg dump_arg_print[2];

    /* Open Netlink route socket */
    if (rtnl_open(&rth, 0) == -1) {
        perror("rtnl_open");
        exit(EXIT_FAILURE);
    }

    /* Request all links */
    if (rtnl_wilddump_request(&rth, 0, RTM_GETLINK) == -1) {
        perror("rtnl_wilddump_request");
        exit(EXIT_FAILURE);
    }

    /* Process results
     * Since iproute2 v3.2.0, rtnl_dump_filter takes 2 arguments instead of 4.
     * To be compatible with both old and new API, use rtnl_dump_filter_l.
     * cf. https://git.kernel.org/cgit/linux/kernel/git/shemminger/iproute2.git/commit/lib/libnetlink.c?id=cd70f3f522e04b4d2fa80ae10292379bf223a53b
     */
    memset(&dump_arg_print, 0, sizeof(dump_arg_print));
    dump_arg_print[0].filter = print_linkaddr_filter;
    rtnl_dump_filter_l(&rth, dump_arg_print);

    rtnl_close(&rth);
    return 0;
}
