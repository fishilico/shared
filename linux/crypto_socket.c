/**
 * Use the Crypto API user-interface provided by the kernel
 *
 * Documentation:
 *   * https://www.kernel.org/doc/htmldocs/crypto-API/index.html
 *   * https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/DocBook/crypto-API.tmpl
 *   * https://github.com/smuellerDD/libkcapi/
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for accept4, snprintf */
#endif

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <linux/if_alg.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef AF_ALG
#    define AF_ALG 38
#endif
#ifndef SOL_ALG
#    define SOL_ALG 279
#endif

/* Copy definitions from include/uapi/linux/cryptouser.h (not provided by linux-api-headers:
 * https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/cryptouser.h
 */
enum {
    CRYPTO_MSG_BASE = 0x10,
    CRYPTO_MSG_NEWALG = 0x10,
    CRYPTO_MSG_DELALG,
    CRYPTO_MSG_UPDATEALG,
    CRYPTO_MSG_GETALG,
    CRYPTO_MSG_DELRNG,
    __CRYPTO_MSG_MAX
};
#define CRYPTO_MAX_ALG_NAME 64
struct crypto_user_alg {
    char cru_name[CRYPTO_MAX_ALG_NAME];
    char cru_driver_name[CRYPTO_MAX_ALG_NAME];
    char cru_module_name[CRYPTO_MAX_ALG_NAME];
    __u32 cru_type;
    __u32 cru_mask;
    __u32 cru_refcnt;
    __u32 cru_flags;
};
#define CR_RTA(x) ((struct rtattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(struct crypto_user_alg))))
enum crypto_attr_type_t {
    CRYPTOCFGA_UNSPEC,
    CRYPTOCFGA_PRIORITY_VAL,
    CRYPTOCFGA_REPORT_LARVAL,
    CRYPTOCFGA_REPORT_HASH,
    CRYPTOCFGA_REPORT_BLKCIPHER,
    CRYPTOCFGA_REPORT_AEAD,
    CRYPTOCFGA_REPORT_COMPRESS,
    CRYPTOCFGA_REPORT_RNG,
    CRYPTOCFGA_REPORT_CIPHER,
    CRYPTOCFGA_REPORT_AKCIPHER,
    CRYPTOCFGA_REPORT_KPP,
    __CRYPTOCFGA_MAX
#define CRYPTOCFGA_MAX (__CRYPTOCFGA_MAX - 1)
};
#define CRYPTO_MAX_NAME CRYPTO_MAX_ALG_NAME
struct crypto_report_larval {
    char type[CRYPTO_MAX_NAME];
};

struct crypto_report_hash {
    char type[CRYPTO_MAX_NAME];
    unsigned int blocksize;
    unsigned int digestsize;
};

struct crypto_report_cipher {
    char type[CRYPTO_MAX_ALG_NAME];
    unsigned int blocksize;
    unsigned int min_keysize;
    unsigned int max_keysize;
};

struct crypto_report_blkcipher {
    char type[CRYPTO_MAX_NAME];
    char geniv[CRYPTO_MAX_NAME];
    unsigned int blocksize;
    unsigned int min_keysize;
    unsigned int max_keysize;
    unsigned int ivsize;
};

struct crypto_report_aead {
    char type[CRYPTO_MAX_NAME];
    char geniv[CRYPTO_MAX_NAME];
    unsigned int blocksize;
    unsigned int maxauthsize;
    unsigned int ivsize;
};

struct crypto_report_comp {
    char type[CRYPTO_MAX_NAME];
};

struct crypto_report_rng {
    char type[CRYPTO_MAX_NAME];
    unsigned int seedsize;
};

struct crypto_report_akcipher {
    char type[CRYPTO_MAX_NAME];
};

struct crypto_report_kpp {
    char type[CRYPTO_MAX_NAME];
};

/* Casts of CMSG_DATA change the required alignment */
#pragma GCC diagnostic ignored "-Wcast-align"

/**
 * Use sha256 through the crypto interface
 */
static bool test_sha256(void)
{
    const char message[] = "Hello, world!";
    const uint8_t expected_digest[32] = {
        0x31, 0x5f, 0x5b, 0xdb, 0x76, 0xd0, 0x78, 0xc4,
        0x3b, 0x8a, 0xc0, 0x06, 0x4e, 0x4a, 0x01, 0x64,
        0x61, 0x2b, 0x1f, 0xce, 0x77, 0xc8, 0x69, 0x34,
        0x5b, 0xfc, 0x94, 0xc7, 0x58, 0x94, 0xed, 0xd3
    };
    uint8_t digest[32];
    struct sockaddr_alg sa;
    int tfmfd, opfd;
    ssize_t bytes;
    size_t i;

    /* Load algif_hash module */
    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    snprintf((char *)sa.salg_type, sizeof(sa.salg_type), "hash");
    snprintf((char *)sa.salg_name, sizeof(sa.salg_name), "sha256");
    tfmfd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (tfmfd == -1) {
        if (errno == EAFNOSUPPORT) {
            /* AF_ALG is not supported by the kernel
             * (missing CONFIG_CRYPTO_USER_API)
             */
            printf("Family AF_ALG not supported by the kernel, continuing.\n");
            return true;
        } else if (errno == EPERM) {
            /* Docker default seccomp policy forbids socket(AF_ALG) */
            printf("Connection to algorithm socket is denied, continuing.\n");
            return true;
        }
        perror("socket");
        return false;
    }
    if (bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        if (errno == ENOENT) {
            /* Module auto-loading has been denied, e.g. by grsecurity
             * GRKERNSEC_MODHARDEN option
             */
            printf("Module algif_hash not found, continuing.\n");
            close(tfmfd);
            return true;
        }
        perror("bind");
        close(tfmfd);
        return false;
    }

    /* Get the operation socket */
    opfd = accept4(tfmfd, NULL, 0, SOCK_CLOEXEC);
    if (opfd == -1) {
        perror("accept");
        close(tfmfd);
        return false;
    }

    /* Hash the message */
    bytes = write(opfd, message, strlen(message));
    if ((size_t)bytes != strlen(message)) {
        if (bytes == -1) {
            perror("write");
        } else {
            fprintf(
                stderr, "Not enough bytes sent: %" PRIuPTR "/%" PRIuPTR "\n",
                bytes, strlen(message));
        }
        close(opfd);
        close(tfmfd);
        return false;
    }
    bytes = read(opfd, digest, sizeof(digest));
    if (bytes != sizeof(digest)) {
        if (bytes == -1) {
            perror("read");
        } else {
            fprintf(
                stderr, "Not enough bytes read: %" PRIuPTR "/%" PRIuPTR "\n",
                bytes, sizeof(digest));
        }
        close(opfd);
        close(tfmfd);
        return false;
    }
    close(opfd);
    close(tfmfd);

    /* Test the result */
    printf("SHA256(%s) = ", message);
    for (i = 0; i < sizeof(digest); i++) {
        printf("%02x", digest[i]);
        if (digest[i] != expected_digest[i]) {
            printf("... invalid!\n");
            return false;
        }
    }
    printf("\n");
    return true;
}

/* clang with Musl warns about a -Wsign-compare warning in CMSG_NXTHDR:
 * error: comparison of integers of different signs: 'unsigned long' and 'long' [-Werror,-Wsign-compare]
 * /usr/include/sys/socket.h:286:44: note: expanded from macro 'CMSG_NXTHDR'
 * __CMSG_LEN(cmsg) + sizeof(struct cmsghdr) >= __MHDR_END(mhdr) - (unsigned char *)(cmsg) */
#if defined(__GNUC__)
#    define HAVE_PRAGMA_GCC_DIAGNOSTIC_PUSH ((__GNUC__ << 16) + __GNUC_MINOR__ >= 0x40005)
#else
#    define HAVE_PRAGMA_GCC_DIAGNOSTIC_PUSH 1
#endif
#if HAVE_PRAGMA_GCC_DIAGNOSTIC_PUSH
#    pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wsign-compare"

/**
 * Use AES-XTS encryption through the crypto interface
 */
static bool test_aes_xts_enc(void)
{
    char message[16] = "Hello, world!!!";
    const uint8_t key[32] = {
        'M', 'y', 'S', 'u', 'p', '3', 'r', 'S',
        '3', 'c', 'r', '3', 't', 'K', '3', 'y',
        '0', 'n', 'T', 'h', '1', 'r', 't', 'y',
        '2', 'B', 'y', 't', '3', 's', '!', '!'
    };
    const uint8_t ivdata[16] = {
        'W', 'h', 'a', 't', 'A', 'B', 'e', 'a',
        'u', 't', 'i', 'f', 'u', 'l', 'I', 'V'
    };
    const uint8_t expected_encrypted[16] = {
        0x69, 0x6d, 0x8f, 0xf2, 0xd7, 0xd2, 0xc8, 0x8b,
        0x08, 0x10, 0xa1, 0x2b, 0x9e, 0xda, 0xb9, 0x38
    };
    uint8_t encrypted[16];
    struct sockaddr_alg sa;
    int tfmfd, opfd;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct af_alg_iv *ivmsg;
    struct iovec iov;
    uint8_t cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)]; /* OP and IV headers */
    ssize_t bytes;
    size_t i;

    /* Sanity check */
    assert(sizeof(*ivmsg) + sizeof(ivdata) == 20);

    /* Select encryption cipher */
    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    snprintf((char *)sa.salg_type, sizeof(sa.salg_type), "skcipher");
    snprintf((char *)sa.salg_name, sizeof(sa.salg_name), "xts(aes)");
    tfmfd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (tfmfd == -1) {
        if (errno == EAFNOSUPPORT) {
            printf("Family AF_ALG not supported by the kernel, continuing.\n");
            return true;
        } else if (errno == EPERM) {
            /* Docker default seccomp policy forbids socket(AF_ALG) */
            printf("Connection to algorithm socket is denied, continuing.\n");
            return true;
        }
        perror("socket");
        return false;
    }
    if (bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("bind");
        close(tfmfd);
        return false;
    }

    if (setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) == -1) {
        int err = errno;
        perror("setsockopt(ALG_SET_KEY)");
        close(tfmfd);
        /* Qemu-user requires a build-time option to use AF_ALG:
         * https://github.com/qemu/qemu/blob/0266c739abbed804deabb4ccde2aa449466ac3b4/configure#L452
         */
        if (err == ENOPROTOOPT) {
            return true;
        }
        return false;
    }

    /* Get the operation socket */
    opfd = accept4(tfmfd, NULL, 0, SOCK_CLOEXEC);
    if (opfd == -1) {
        perror("accept");
        close(tfmfd);
        return false;
    }

    /* Build a message to send to the operation socket */
    memset(&msg, 0, sizeof(msg));
    memset(&cbuf, 0, sizeof(cbuf));
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(4);
    *(uint32_t *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(20);
    assert(sizeof(ivdata) == 16);
    ivmsg = (struct af_alg_iv *)CMSG_DATA(cmsg);
    ivmsg->ivlen = sizeof(ivdata);
    memcpy(ivmsg->iv, ivdata, sizeof(ivdata));

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = message;
    iov.iov_len = sizeof(message);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    /* Encrypt data */
    bytes = sendmsg(opfd, &msg, 0);
    if ((size_t)bytes != sizeof(message)) {
        if (bytes == -1) {
            perror("sendmsg");
        } else {
            fprintf(
                stderr, "Not enough bytes sent: %" PRIuPTR "/%" PRIuPTR "\n",
                bytes, sizeof(message));
        }
        close(opfd);
        close(tfmfd);
        return false;
    }
    bytes = read(opfd, encrypted, sizeof(encrypted));
    if (bytes != sizeof(encrypted)) {
        if (bytes == -1) {
            perror("read");
        } else {
            fprintf(
                stderr, "Not enough bytes read: %" PRIuPTR "/%" PRIuPTR "\n",
                bytes, sizeof(encrypted));
        }
        close(opfd);
        close(tfmfd);
        return false;
    }
    close(opfd);
    close(tfmfd);

    /* Test the result */
    printf("AES-XTS-enc(%s\\0, key=%.32s, IV=%.16s) = ", message, key, ivdata);
    for (i = 0; i < sizeof(encrypted); i++) {
        printf("%02x", encrypted[i]);
        if (encrypted[i] != expected_encrypted[i]) {
            printf("... invalid!\n");
            return false;
        }
    }
    printf("\n");
    return true;
}

/**
 * Use AES-CBC decryption through the crypto interface
 * Decrypt the result of:
 *     echo 'Hello, world!' |openssl enc -aes-256-cbc -nosalt -K 4d7953757033725333637233744b3379 -iv ''
 */
static bool test_aes_cbc_dec(void)
{
    uint8_t encrypted[16] = {
        0x43, 0x43, 0xec, 0x7d, 0x76, 0x99, 0x49, 0x61,
        0xd9, 0x0e, 0x3f, 0x2e, 0xfe, 0xc9, 0x2c, 0xb3
    };
    const uint8_t key[32] = {
        'M', 'y', 'S', 'u', 'p', '3', 'r', 'S',
        '3', 'c', 'r', '3', 't', 'K', '3', 'y',
    };
    const uint8_t expected_decrypted[16] = {
        'H', 'e', 'l', 'l', 'o', ',', ' ', 'w',
        'o', 'r', 'l', 'd', '!', '\n', 2, 2
    };
    uint8_t decrypted[16];
    struct sockaddr_alg sa;
    int tfmfd, opfd;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct af_alg_iv *ivmsg;
    struct iovec iov;
    uint8_t cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)]; /* OP and IV headers */
    ssize_t bytes;
    size_t i;

    /* Select encryption cipher */
    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    snprintf((char *)sa.salg_type, sizeof(sa.salg_type), "skcipher");
    snprintf((char *)sa.salg_name, sizeof(sa.salg_name), "cbc(aes)");
    tfmfd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (tfmfd == -1) {
        if (errno == EAFNOSUPPORT) {
            printf("Family AF_ALG not supported by the kernel, continuing.\n");
            return true;
        } else if (errno == EPERM) {
            /* Docker default seccomp policy forbids socket(AF_ALG) */
            printf("Connection to algorithm socket is denied, continuing.\n");
            return true;
        }
        perror("socket");
        return false;
    }
    if (bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("bind");
        close(tfmfd);
        return false;
    }

    if (setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) == -1) {
        int err = errno;
        perror("setsockopt(ALG_SET_KEY)");
        close(tfmfd);
        /* Qemu-user requires a build-time option to use AF_ALG */
        if (err == ENOPROTOOPT) {
            return true;
        }
        return false;
    }

    /* Get the operation socket */
    opfd = accept4(tfmfd, NULL, 0, SOCK_CLOEXEC);
    if (opfd == -1) {
        perror("accept");
        close(tfmfd);
        return false;
    }

    /* Build a message to send to the operation socket */
    memset(&msg, 0, sizeof(msg));
    memset(&cbuf, 0, sizeof(cbuf));
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(4);
    *(uint32_t *)CMSG_DATA(cmsg) = ALG_OP_DECRYPT;

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(20);
    ivmsg = (struct af_alg_iv *)CMSG_DATA(cmsg);
    ivmsg->ivlen = 16;
    /* IV is left empty */

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = encrypted;
    iov.iov_len = sizeof(encrypted);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    /* Decrypt data */
    bytes = sendmsg(opfd, &msg, 0);
    if ((size_t)bytes != sizeof(encrypted)) {
        if (bytes == -1) {
            perror("sendmsg");
        } else {
            fprintf(
                stderr, "Not enough bytes sent: %" PRIuPTR "/%" PRIuPTR "\n",
                bytes, sizeof(encrypted));
        }
        close(opfd);
        close(tfmfd);
        return false;
    }
    bytes = read(opfd, decrypted, sizeof(decrypted));
    if (bytes != sizeof(decrypted)) {
        if (bytes == -1) {
            perror("read");
        } else {
            fprintf(
                stderr, "Not enough bytes read: %" PRIuPTR "/%" PRIuPTR "\n",
                bytes, sizeof(decrypted));
        }
        close(opfd);
        close(tfmfd);
        return false;
    }
    close(opfd);
    close(tfmfd);

    /* Test the result */
    printf("AES-CBC-dec(..., key=%.16s, IV=0) = ", key);
    for (i = 0; i < sizeof(decrypted); i++) {
        if (decrypted[i] >= 32 && decrypted[i] < 127) {
            printf("%c", decrypted[i]);
        } else {
            printf("\\x%02x", decrypted[i]);
        }
        if (decrypted[i] != expected_decrypted[i]) {
            printf("... invalid!\n");
            return false;
        }
    }
    printf("\n");
    return true;
}
#if HAVE_PRAGMA_GCC_DIAGNOSTIC_PUSH
#    pragma GCC diagnostic pop
#endif

/**
 * Retrieve information about algorithms from the kernel using a netlink crypto socket.
 * Such information may also be available through /proc/crypto.
 */
static bool show_cipher_info(const char *ciphername)
{
    int nlsock;
    struct sockaddr_nl sanl;
    socklen_t addr_len;
    struct {
        struct nlmsghdr hdr;
        struct crypto_user_alg cru;
    } request;
    struct iovec iov;
    struct msghdr msg;
    ssize_t bytes;
    uint8_t buffer[4096];
    struct nlmsghdr *reply_hdr;
    struct nlmsgerr *reply_err;
    struct crypto_user_alg *reply_cru;
    struct rtattr *rta;

    /* Open a netlink crypto socket */
    nlsock = socket(AF_NETLINK, SOCK_RAW, NETLINK_CRYPTO);
    if (nlsock < 0) {
        if (errno == EPROTONOSUPPORT) {
            /* Module auto-loading has been denied, e.g. by grsecurity
             * GRKERNSEC_MODHARDEN option
             */
            printf("Module crypto_user not found, continuing.\n");
            return true;
        }
        if (errno == EPFNOSUPPORT) {
            /* Qemu-user does not support the protocol family */
            printf("Protocol family not supported, continuing.\n");
            return true;
        }
        perror("socket");
        return false;
    }

    memset(&sanl, 0, sizeof(sanl));
    sanl.nl_family = AF_NETLINK;
    if (bind(nlsock, (struct sockaddr *)&sanl, sizeof(sanl)) < 0) {
        perror("bind");
        close(nlsock);
        return false;
    }

    /* Sanity check */
    addr_len = sizeof(sanl);
    if (getsockname(nlsock, (struct sockaddr *)&sanl, &addr_len) < 0) {
        perror("getsockname");
        close(nlsock);
        return false;
    }
    assert(addr_len == sizeof(sanl));
    assert(sanl.nl_family == AF_NETLINK);

    /* Build and send request */
    memset(&request, 0, sizeof(request));

    request.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(request.cru));
    request.hdr.nlmsg_flags = NLM_F_REQUEST;
    request.hdr.nlmsg_type = CRYPTO_MSG_GETALG;
    request.hdr.nlmsg_seq = (uint32_t)time(NULL);
    assert(strlen(ciphername) < sizeof(request.cru.cru_name));
    strncpy(request.cru.cru_name, ciphername, sizeof(request.cru.cru_name));

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)&request;
    iov.iov_len = request.hdr.nlmsg_len;

    memset(&sanl, 0, sizeof(sanl));
    sanl.nl_family = AF_NETLINK;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sanl;
    msg.msg_namelen = sizeof(sanl);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    bytes = sendmsg(nlsock, &msg, 0);
    if ((size_t)bytes != request.hdr.nlmsg_len) {
        if (bytes == -1) {
            if (errno == ECONNREFUSED) {
                /* This happens in containers */
                printf("Connection to crypto Netlink socket refused, continuing.\n");
                close(nlsock);
                return true;
            } else {
                perror("sendmsg");
            }
        } else {
            fprintf(
                stderr, "Not enough bytes sent: %" PRIuPTR "/%u\n",
                bytes, request.hdr.nlmsg_len);
        }
        close(nlsock);
        return false;
    }
    /* FIXME: this generates the following warning on Linux 4.5:
     * netlink: 208 bytes leftover after parsing attributes in process `crypto_socket.b'.
     * (https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/lib/nlattr.c?h=v4.5#n205)
     * ... and strace states:
     * sendmsg(3, {
     *   msg_name={sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000},
     *   msg_namelen=12,
     *   msg_iov=[{
     *     iov_base={
     *       {len=224, type=0x13, flags=NLM_F_REQUEST, seq=1470763108, pid=0},
     *       "ccm(aes)\0\0\0\0\0\0\0[...]\0\0"},
     *     iov_len=224}],
     *   msg_iovlen=1,
     *   msg_controllen=0,
     *   msg_flags=0}, 0) = 224
     *
     * 224 - 208 = 16 bytes have been processed by nla_parse(). Why?
     */

    /* Read reply */
    memset(buffer, 0, sizeof(buffer));
    bytes = read(nlsock, buffer, sizeof(buffer));
    if (bytes == -1) {
        perror("read");
        close(nlsock);
        return false;
    } else if (bytes < (ssize_t)sizeof(struct nlmsghdr)) {
        fprintf(
            stderr, "Not enough bytes read: %" PRIuPTR "/%" PRIuPTR "\n",
            bytes, sizeof(buffer));
        close(nlsock);
        return false;
    } else if (bytes > (ssize_t)sizeof(buffer)) {
        fprintf(
            stderr, "Too many bytes read: %" PRIuPTR "/%" PRIuPTR "\n",
            bytes, sizeof(buffer));
        close(nlsock);
        return false;
    }

    /* Close the socket now that it is no longer needed */
    close(nlsock);

    /* Decode the received data */
    reply_hdr = (struct nlmsghdr *)buffer;
    if (reply_hdr->nlmsg_type == NLMSG_ERROR) {
        /* Try to decode the error code if there is enough space for a nlmsgerr structure */
        if (reply_hdr->nlmsg_len != (size_t)bytes || (size_t)bytes < NLMSG_SPACE(sizeof(*reply_err))) {
            fprintf(stderr, "Netlink returned an invalid NLMSG_ERROR reply.\n");
            return false;
        }
        reply_err = NLMSG_DATA(reply_hdr);
        /* Skip ciphers which are not available */
        if (reply_err->error == -ENOENT) {
            /* stdrng may not be available */
            if (!strcmp(ciphername, "stdrng")) {
                printf("No crypto-stdrng loaded (ansi_cprng or drbg), continuing.\n");
                return true;
            }
            printf("Module crypto-%s not found, continuing.\n", ciphername);
            return true;
        }
        fprintf(
            stderr, "Netlink returned NLMSG_ERROR with code %d: %s.\n",
            reply_err->error, strerror(-reply_err->error));
        return false;
    }
    if (reply_hdr->nlmsg_type != CRYPTO_MSG_GETALG) {
        fprintf(
            stderr, "Unexpected Netlink message type: %d instead of %d\n",
            reply_hdr->nlmsg_type, CRYPTO_MSG_GETALG);
        return false;
    }
    if (reply_hdr->nlmsg_len != (size_t)bytes) {
        fprintf(
            stderr, "Unexpected Netlink message size: %u advertized but %" PRIuPTR " received\n",
            reply_hdr->nlmsg_len, bytes);
        return false;
    }

    reply_cru = NLMSG_DATA(reply_hdr);
    bytes -= NLMSG_SPACE(sizeof(*reply_cru));
    if (bytes < 0) {
        fprintf(stderr, "Not enough bytes received from Netlink socket\n");
        return false;
    }

    printf("Information about %s:\n", ciphername);
    printf("  * Name: %.*s\n", (int)sizeof(reply_cru->cru_name), reply_cru->cru_name);
    printf("  * Driver name: %.*s\n", (int)sizeof(reply_cru->cru_driver_name), reply_cru->cru_driver_name);
    printf("  * Module name: %.*s\n", (int)sizeof(reply_cru->cru_module_name), reply_cru->cru_module_name);
    if (reply_cru->cru_type)
        printf("  * Type: %u\n", reply_cru->cru_type);
    if (reply_cru->cru_mask)
        printf("  * Mask: %#x\n", reply_cru->cru_mask);
    printf("  * Reference count: %u\n", reply_cru->cru_refcnt);
    /* Flags are CRYPTO_ALG_... constants from include/linux/crypto.h in Linux source tree */
    printf("  * Flags: %#x\n", reply_cru->cru_flags);
    for (rta = CR_RTA(reply_cru); RTA_OK(rta, bytes); rta = RTA_NEXT(rta, bytes)) {
        switch (rta->rta_type) {
            case CRYPTOCFGA_UNSPEC:
                printf("  * Unspecified data of size %lu bytes\n", (unsigned long)RTA_PAYLOAD(rta));
                break;
            case CRYPTOCFGA_PRIORITY_VAL:
                if (RTA_PAYLOAD(rta) != 4) {
                    fprintf(stderr, "Unexpected size for CRYPTOCFGA_PRIORITY_VAL payload\n");
                    return false;
                }
                printf("  * Priority %" PRIu32 "\n", *(uint32_t *)RTA_DATA(rta));
                break;
            case CRYPTOCFGA_REPORT_LARVAL:
                printf("  * Larval (%lu bytes)\n", (unsigned long)RTA_PAYLOAD(rta));
                break;
            case CRYPTOCFGA_REPORT_HASH:
                printf("  * Hash (%lu bytes)\n", (unsigned long)RTA_PAYLOAD(rta));
                if (RTA_PAYLOAD(rta) == sizeof(struct crypto_report_hash)) {
                    struct crypto_report_hash *rhash = (struct crypto_report_hash *)RTA_DATA(rta);

                    printf("    - type: %.*s\n", (int)sizeof(rhash->type), rhash->type);
                    printf("    - block size: %u\n", rhash->blocksize);
                    printf("    - digest size: %u\n", rhash->digestsize);
                }
                break;
            case CRYPTOCFGA_REPORT_BLKCIPHER:
                printf("  * BlkCipher (%lu bytes)\n", (unsigned long)RTA_PAYLOAD(rta));
                if (RTA_PAYLOAD(rta) == sizeof(struct crypto_report_blkcipher)) {
                    struct crypto_report_blkcipher *rblk = (struct crypto_report_blkcipher *)RTA_DATA(rta);

                    printf("    - type: %.*s\n", (int)sizeof(rblk->type), rblk->type);
                    printf("    - geniv: %.*s\n", (int)sizeof(rblk->geniv), rblk->geniv);
                    printf("    - block size: %u\n", rblk->blocksize);
                    printf("    - minimum key size: %u\n", rblk->min_keysize);
                    printf("    - maximum key size: %u\n", rblk->max_keysize);
                    printf("    - iv size: %u\n", rblk->ivsize);
                }
                break;
            case CRYPTOCFGA_REPORT_AEAD:
                printf("  * AEAD (%lu bytes)\n", (unsigned long)RTA_PAYLOAD(rta));
                if (RTA_PAYLOAD(rta) == sizeof(struct crypto_report_aead)) {
                    struct crypto_report_aead *raead = (struct crypto_report_aead *)RTA_DATA(rta);

                    printf("    - type: %.*s\n", (int)sizeof(raead->type), raead->type);
                    printf("    - geniv: %.*s\n", (int)sizeof(raead->geniv), raead->geniv);
                    printf("    - block size: %u\n", raead->blocksize);
                    printf("    - maximum authentication size: %u\n", raead->maxauthsize);
                    printf("    - iv size: %u\n", raead->ivsize);
                }
                break;
            case CRYPTOCFGA_REPORT_COMPRESS:
                printf("  * Compress (%lu bytes)\n", (unsigned long)RTA_PAYLOAD(rta));
                break;
            case CRYPTOCFGA_REPORT_RNG:
                printf("  * RNG (%lu bytes)\n", (unsigned long)RTA_PAYLOAD(rta));
                if (RTA_PAYLOAD(rta) == sizeof(struct crypto_report_rng)) {
                    struct crypto_report_rng *rrng = (struct crypto_report_rng *)RTA_DATA(rta);

                    printf("    - type: %.*s\n", (int)sizeof(rrng->type), rrng->type);
                    printf("    - seed size: %u\n", rrng->seedsize);
                }
                break;
            case CRYPTOCFGA_REPORT_CIPHER:
                printf("  * Cipher (%lu bytes)\n", (unsigned long)RTA_PAYLOAD(rta));
                break;
            case CRYPTOCFGA_REPORT_AKCIPHER:
                printf("  * AkCipher (%lu bytes)\n", (unsigned long)RTA_PAYLOAD(rta));
                break;
            case CRYPTOCFGA_REPORT_KPP:
                printf("  * KPP (%lu bytes)\n", (unsigned long)RTA_PAYLOAD(rta));
                break;
            default:
                printf("  * Unhandled type %u (%lu bytes)\n", rta->rta_type,
                       (unsigned long)RTA_PAYLOAD(rta));
        }
    }
    if (bytes) {
        fprintf(stderr, "Unprocessed %" PRIuPTR " bytes after attributes\n", bytes);
        return false;
    }
    return true;
}

int main(void)
{
    if (!test_sha256()) {
        fprintf(stderr, "SHA256 test failed.\n");
        return 1;
    }
    if (!test_aes_xts_enc()) {
        fprintf(stderr, "AES-XTS encryption test failed.\n");
        return 1;
    }
    if (!test_aes_cbc_dec()) {
        fprintf(stderr, "AES-CBC decryption test failed.\n");
        return 1;
    }
    if (!show_cipher_info("sha256")) {
        fprintf(stderr, "Failed to show information about sha256.\n");
        return 1;
    }
    if (!show_cipher_info("xts(aes)")) {
        fprintf(stderr, "Failed to show information about xts(aes).\n");
        return 1;
    }
    if (!show_cipher_info("ccm(aes)")) {
        fprintf(stderr, "Failed to show information about ccm(aes).\n");
        return 1;
    }
    if (!show_cipher_info("stdrng")) {
        fprintf(stderr, "Failed to show information about stdrng.\n");
        return 1;
    }
    return 0;
}
