/**
 * Create two children and pass a file descriptor between them using a Unix socket
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for accept4, clock_gettime, mkdtemp, pipe2, snprintf */
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h> /* for offsetof */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h> /* for NAME_MAX */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* from Linux kernel, include/linux/net.h and include/linux/socket.h */
#ifndef SOCK_PASSSEC
#    define SOCK_PASSSEC 4
#endif
#ifndef SCM_SECURITY
#    define SCM_SECURITY 0x03
#endif

/* clang warns that CMSG_NXTHDR increases the required alignment of a pointer */
#if defined(__GNUC__)
#    define HAVE_PRAGMA_GCC_DIAGNOSTIC_PUSH ((__GNUC__ << 16) + __GNUC_MINOR__ >= 0x40005)
#else
#    define HAVE_PRAGMA_GCC_DIAGNOSTIC_PUSH 1
#endif
#if HAVE_PRAGMA_GCC_DIAGNOSTIC_PUSH
#    pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wcast-align"
#pragma GCC diagnostic ignored "-Wsign-compare"
static int child1_main(const char *sockpath)
{
    struct sockaddr_un addr;
    struct iovec iov;
    struct msghdr msg;
    union {
        struct cmsghdr cmsghdr;
        uint8_t buf[
            CMSG_SPACE(sizeof(int)) +
            CMSG_SPACE(sizeof(struct ucred)) +
            CMSG_SPACE(NAME_MAX)];
    } control;
    struct cmsghdr *cmsg;
    struct ucred cred;
    int sockfd, clientfd, fd, on = 1;
    socklen_t addrlen = sizeof(addr);
    char buffer[4096];
    ssize_t bytes;
    size_t len;

    /* Create a Unix socket */
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }
    if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) {
        perror("fcntl(CLOEXEC)");
        close(sockfd);
        return 1;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) == -1) {
        perror("setsockopt(PASSCRED)");
        /* This is a warning, not a fatal error. */
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_PASSSEC, &on, sizeof(on)) == -1) {
        perror("setsockopt(PASSSEC)");
        /* This is a warning, not a fatal error. */
    }
    umask(0777 & ~(S_IRUSR | S_IWUSR));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
    if (bind(sockfd, (struct sockaddr *)(&addr), sizeof(addr)) == -1) {
        perror("bind");
        return 1;
    }
    if (listen(sockfd, 42) == -1) {
        perror("listen");
        return 1;
    }
    printf("[%u] Created Unix socket %s\n", getpid(), sockpath);

    /* Wait for an incoming connection */
    clientfd = accept4(sockfd, (struct sockaddr *)&addr, &addrlen, SOCK_CLOEXEC);
    if (clientfd == -1) {
        perror("accept");
        return 1;
    }
    assert(addrlen <= sizeof(addr));
    printf("[%u] Accepted client on %s\n", getpid(), addr.sun_path);
    close(sockfd);

    /* Receive a file descriptor */
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer) - 1;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &control;
    msg.msg_controllen = sizeof(control);
    bytes = recvmsg(clientfd, &msg, MSG_NOSIGNAL | MSG_CMSG_CLOEXEC);
    if (bytes < 0) {
        perror("recvmsg");
        return 1;
    }
    buffer[bytes] = '\0';
    printf("[%u] Received %ld bytes: %s\n", getpid(), (long)bytes, buffer);

    fd = -1;
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET) {
            printf("[%u] * unknown control message %d-%d\n",
                   getpid(), cmsg->cmsg_level, cmsg->cmsg_type);
            continue;
        }
        if (cmsg->cmsg_type == SCM_RIGHTS) {
            if (cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
                printf("[%u] * Invalid message size for fd (%lu)!\n",
                       getpid(), (unsigned long)cmsg->cmsg_len);
                return 1;
            }
            memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
            printf("[%u] * File descriptor: %d\n", getpid(), fd);
        } else if (cmsg->cmsg_type == SCM_CREDENTIALS) {
            if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
                printf("[%u] * Invalid message size for creds (%lu)!\n",
                       getpid(), (unsigned long)cmsg->cmsg_len);
                return 1;
            }
            memcpy(&cred, CMSG_DATA(cmsg), sizeof(struct ucred));
            printf("[%u] * Credentials: %u:%u@%u\n", getpid(),
                   cred.uid, cred.gid, cred.pid);
        } else if (cmsg->cmsg_type == SCM_SECURITY) {
            len = cmsg->cmsg_len - CMSG_LEN(0);
            if (len >= sizeof(buffer)) {
                len = sizeof(buffer) - 1;
            }
            memcpy(buffer, CMSG_DATA(cmsg), len);
            buffer[len] = '\0';
            printf("[%u] * Security label: %s\n", getpid(), buffer);
        } else {
            printf("[%u] * unknown control message type %d\n",
                   getpid(), cmsg->cmsg_type);
        }
    }
    if (fd == -1) {
        fprintf(stderr, "[%u] No fd in received message!\n", getpid());
        return 1;
    }
    close(clientfd);

    /* Write a message in the fd */
    snprintf(buffer, sizeof(buffer), "Hello world, here is pid %u!", getpid());
    bytes = write(fd, buffer, strlen(buffer));
    if (bytes < 0) {
        perror("write");
        return 1;
    }
    printf("[%u] Wrote message to the fd\n", getpid());
    close(fd);
    return 0;
}
#if HAVE_PRAGMA_GCC_DIAGNOSTIC_PUSH
#    pragma GCC diagnostic pop
#endif

static int child2_main(const char *sockpath)
{
    int sockfd = -1, pipefd[2];
    struct sockaddr_un addr;
    struct iovec iov;
    struct msghdr msg;
    union {
        struct cmsghdr cmsghdr;
        uint8_t buf[CMSG_SPACE(sizeof(int))];
    } control;
    struct cmsghdr *cmsg;
    char buffer[4096];
    ssize_t bytes;

    /* Create a pipe */
    if (pipe2(pipefd, O_CLOEXEC) == -1) {
        perror("pipe");
        return 1;
    }

    /* Wait for the socket to appear */
    while (access(sockpath, F_OK) != 0) {
        if (errno != ENOENT) {
            perror("access");
            return 1;
        }
        usleep(1);
    }

    /* Connect to the Unix socket */
    while (sockfd == -1) {
        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sockfd == -1) {
            perror("socket");
            return 1;
        }
        if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) {
            perror("fcntl(CLOEXEC)");
            return 1;
        }
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
        if (connect(sockfd, (struct sockaddr *)(&addr), sizeof(addr)) == -1) {
            /* There is a race condition between bind() and listen() calls.
             * If connect() falls in it, it fails with ECONNREFUSED error.
             * Then sleeps a little and try again.
             */
            if (errno == ECONNREFUSED) {
                printf("[%u] Failed to connect because of a race condition, trying again.\n",
                       getpid());
                close(sockfd);
                sockfd = -1;
                usleep(1);
                continue;
            }
            perror("connect");
            return 1;
        }
    }
    printf("[%u] Connected to the socket\n", getpid());

    /* Send the write size of the pipe over the socket */
    memset(&control, 0, sizeof(control));
    memset(&iov, 0, sizeof(iov));
    snprintf(buffer, sizeof(buffer), "Here is a fd from process %u!", getpid());
    iov.iov_base = buffer;
    iov.iov_len = strlen(buffer);
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &control;
    msg.msg_controllen = sizeof(control);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &pipefd[1], sizeof(int));
    if (sendmsg(sockfd, &msg, MSG_NOSIGNAL) < 0) {
        perror("sendmsg");
        return 1;
    }
    printf("[%u] Sent a pipe over the socket\n", getpid());
    close(sockfd);
    close(pipefd[1]);

    /* Receive data from the file descriptor */
    bytes = read(pipefd[0], buffer, sizeof(buffer) - 1);
    if (bytes == -1) {
        perror("read");
        return 1;
    }
    if (bytes == 0) {
        fprintf(stderr, "[%u] The pipe did not received anything!\n", getpid());
        return 1;
    }
    assert(bytes >= 0);
    buffer[bytes] = '\0';
    printf("[%u] Read %ld bytes from the pipe: %s\n", getpid(), (long)bytes, buffer);
    close(pipefd[0]);
    return 0;
}

/**
 * Build as much sockets as possible in a "recursive" way, by sending them one into the other.
 * This may slow the system down. In order to prevent this, define a sane limit
 * /proc/sys/fs/file-max, such as 20000.
 */
static int recursive_sockets(void)
{
    int recur_sockfd[2] = { -1 }, sockv[2];
    char buffer[1] = { '!' };
    struct iovec iov;
    union {
        struct cmsghdr cmsghdr;
        uint8_t buf[CMSG_SPACE(sizeof(int[2]))];
    } control;
    struct msghdr msg;
    unsigned int count;
    struct timespec tv;
    time_t start_time;

    memset(&tv, 0, sizeof(tv));
    if (clock_gettime(CLOCK_MONOTONIC, &tv) == -1) {
        /* In Fedora 32 Docker environment, clock_gettime() uses
         * syscall clock_gettime64(), which is denied:
         *    clock_gettime64(CLOCK_MONOTONIC, 0xffdd20ec) = -1 EPERM (Operation not permitted)
         */
#ifdef __i386__
        if (errno == EPERM) {
            printf("Unable to get the Monotonic clock, probably due to 32-bit/64-bit compatibility issues.\n");
            return 0;
        }
#endif
        perror("clock_gettime(MONOTONIC)");
        return 1;
    }
    start_time = tv.tv_sec;

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = buffer;
    iov.iov_len = strlen(buffer);

    memset(&control, 0, sizeof(control));

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &control;
    msg.msg_controllen = sizeof(control);

    printf("Trying to hit the recursive fd-socket sending limit...\n");
    for (count = 0; count < 65536; count++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockv) == -1) {
            if (errno == ENFILE || errno == EMFILE) {
                /* "Too many open files in system" or "Too many open files"
                 * This occurs when /proc/sys/fs/file-nr reaches file-max
                 */
                printf("Reached the maximum number of open files on the system.\n");
                break;
            }
            perror("socketpair");
            return 1;
        }
        if (recur_sockfd[0] >= 0) {
            struct cmsghdr *cmsg;

            /* Send recur_sockfd to the newly-created pair */
            cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type = SCM_RIGHTS;
            cmsg->cmsg_len = CMSG_LEN(sizeof(int[2]));
            memcpy(CMSG_DATA(cmsg), recur_sockfd, sizeof(int[2]));
            if (sendmsg(sockv[0], &msg, MSG_NOSIGNAL) < 0) {
                if (errno == ETOOMANYREFS) {
                    printf("Maximum socket depth: %u\n", count);
                    close(recur_sockfd[0]);
                    close(recur_sockfd[1]);
                    close(sockv[0]);
                    close(sockv[1]);
                    return 0;
                }
                perror("sendmsg");
                return 1;
            }
            close(recur_sockfd[0]);
            close(recur_sockfd[1]);
        }
        recur_sockfd[0] = sockv[0];
        recur_sockfd[1] = sockv[1];

        /* Timeout after one minute */
        if (clock_gettime(CLOCK_MONOTONIC, &tv) == -1) {
            perror("clock_gettime(MONOTONIC)");
            return 1;
        }
        if (tv.tv_sec - start_time >= 60) {
            printf(
                "... sent %u socket pairs in %lu seconds, too slow! Aborting the test.\n",
                count, (unsigned long)(tv.tv_sec - start_time));
            close(recur_sockfd[0]);
            close(recur_sockfd[1]);
            return 0;
        }
    }
    printf(
        "Socket depth limit not reached before %u sent socket pairs in %lu seconds\n",
        count, (unsigned long)(tv.tv_sec - start_time));
    if (recur_sockfd[0] >= 0) {
        close(recur_sockfd[0]);
        close(recur_sockfd[1]);
    }
    return 0;
}

int main(void)
{
    const char unixfile[] = "unix.sock";
    char template[] = "/tmp/pass-fd-XXXXXX", *dirpath;
    char sockpath[sizeof(template) + sizeof(unixfile)];
    pid_t child1, child2, pid;
    int status = 0, return_value = 0;

    /* Create a dir which will contains a Unix socket */
    dirpath = mkdtemp(template);
    if (!dirpath) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(sockpath, sizeof(sockpath), "%s/%s", dirpath, unixfile);

    /* Create first child */
    child1 = fork();
    if (child1 == -1) {
        perror("fork");
        return 1;
    } else if (child1 == 0) {
        printf("[%u] Start first child\n", getpid());
        exit(child1_main(sockpath));
    }

    /* Create second child */
    child2 = fork();
    if (child2 == -1) {
        perror("fork");
        return 1;
    } else if (child2 == 0) {
        printf("[%u] Start second child\n", getpid());
        exit(child2_main(sockpath));
    }

    /* Wait for the children */
    for (;;) {
        pid = waitpid(-1, &status, 0);
        if (pid == -1) {
            /* When there is no child left, break free */
            if (errno == ECHILD) {
                break;
            }
            perror("waitpid");
            return 1;
        }
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) != EXIT_SUCCESS) {
                fprintf(stderr, "Child %u exited with status %d\n", pid, WEXITSTATUS(status));
                return_value = 1;
            } else {
                printf("[parent] Child %u successfully exited\n", pid);
            }
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr, "Child %u was killed by signal %d\n", pid, WTERMSIG(status));
            return_value = 1;
        } else if (WIFSTOPPED(status)) {
            fprintf(stderr, "Child %u has been stopped by signal %d\n", pid, WSTOPSIG(status));
            return_value = 1;
        } else {
            fprintf(stderr, "Child %u has been waited with unexpected status %d\n", pid, status);
            return_value = 1;
        }
    }

    /* Remove the socket if it still exists */
    if (access(sockpath, F_OK) == 0) {
        if (unlink(sockpath) == -1) {
            perror("unlink");
            return 1;
        }
    }

    /* Remove the temporary directory */
    if (rmdir(dirpath) == -1) {
        perror("rmdir");
        return 1;
    }

    if (!return_value) {
        /* Have fun with recursive socket sending */
        return_value = recursive_sockets();
    }
    return return_value;
}
