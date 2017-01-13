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
 * * limnl rtnl-link-dump example:
 *   https://git.netfilter.org/libmnl/tree/examples/rtnl/rtnl-link-dump3.c
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for getpagesize (MNL_SOCKET_BUFFER_SIZE) */
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>

static int print_linkaddr_cb(
    const struct nlmsghdr *nlh,
    void *data __attribute__ ((unused)))
{
    struct ifinfomsg *ifim = mnl_nlmsg_get_payload(nlh);
    struct nlattr *attr, *attr_name = NULL, *attr_addr = NULL;

    if (nlh->nlmsg_type != RTM_NEWLINK)
        return MNL_CB_OK;

    /* Gather information about the link */
    mnl_attr_for_each(attr, nlh, sizeof(*ifim)) {
        switch (mnl_attr_get_type(attr)) {
            case IFLA_IFNAME:
                attr_name = attr;
                break;
            case IFLA_ADDRESS:
                attr_addr = attr;
                break;
        }
    }

    /* Display it */
    printf("%d: ", ifim->ifi_index);
    if (attr_name) {
        if (mnl_attr_validate(attr_name, MNL_TYPE_STRING) < 0) {
            perror("mnl_attr_validate(name)");
            return MNL_CB_ERROR;
        }
        printf("%s: ", mnl_attr_get_str(attr_name));
    }
    if (attr_addr) {
        unsigned char *addr = mnl_attr_get_payload(attr_addr);
        uint16_t len = mnl_attr_get_payload_len(attr_addr), pos;
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
    return MNL_CB_OK;
}

int main(void)
{
    struct nlmsghdr *nlh;
    struct rtgenmsg *rt;
    struct mnl_socket *nl;
    unsigned int seq, portid;
    ssize_t nbytes;
    int ret = 0;
    void *buffer;

    buffer = malloc((size_t)MNL_SOCKET_BUFFER_SIZE);
    if (!buffer) {
        fprintf(stderr, "Out of memory\n");
        exit(EXIT_FAILURE);
    }

    /* Open Netlink route socket */
    nl = mnl_socket_open(NETLINK_ROUTE);
    if (nl == NULL) {
        perror("mnl_socket_open");
        exit(EXIT_FAILURE);
    }
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        exit(EXIT_FAILURE);
    }
    portid = mnl_socket_get_portid(nl);

    /* Request all links */
    nlh = mnl_nlmsg_put_header(buffer);
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = (unsigned int)time(NULL);
    rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
    rt->rtgen_family = AF_PACKET;
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_sendto");
        exit(EXIT_FAILURE);
    }

    /* Process results */
    nbytes = mnl_socket_recvfrom(nl, buffer, (size_t)MNL_SOCKET_BUFFER_SIZE);
    while (nbytes > 0) {
        ret = mnl_cb_run(buffer, (size_t)nbytes, seq, portid, print_linkaddr_cb, NULL);
        if (ret <= MNL_CB_STOP)
            break;
        nbytes = mnl_socket_recvfrom(nl, buffer, (size_t)MNL_SOCKET_BUFFER_SIZE);
    }
    if (nbytes == -1) {
        perror("mnl_socket_recvfrom");
        exit(EXIT_FAILURE);
    }

    mnl_socket_close(nl);
    free(buffer);
    return (ret == MNL_CB_STOP) ? 0 : 1;
}
