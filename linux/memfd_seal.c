/**
 * Use memfd (memory file descriptor) and seals
 *
 * According to http://man7.org/linux/man-pages/man2/memfd_create.2.html :
 *     The memfd_create() system call first appeared in Linux 3.17.
 *     glibc support was added in version 2.27.
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for memfd_create */
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifdef __NR_memfd_create

/**
 * memfd_create() and its constants have been introduced in glibc 2.27 by
 * commit 7911dd47da73 ("Linux: Introduce <bits/mman-shared.h>")
 * https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commitdiff;h=7911dd47da73026acc930564c10a1ceeb68d8583
 */
#    ifndef MFD_CLOEXEC
#        define MFD_CLOEXEC 1U
#        define MFD_ALLOW_SEALING 2U
static int memfd_create(const char *name, unsigned int flags)
{
    return (int)syscall(__NR_memfd_create, name, flags);
}
#    endif /* MFD_CLOEXEC */

/**
 * sealing interfaces were added to glibc 2.27 by commit 27342d178344
 * ("Add fcntl sealing interfaces from Linux 3.17 to bits/fcntl-linux.h.")
 * https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commitdiff;h=27342d1783449fe837ac42e9b382b2868af3256f
 */
#    ifndef F_SEAL_SEAL
#        define F_SEAL_SEAL     0x0001
#        define F_SEAL_SHRINK   0x0002
#        define F_SEAL_GROW     0x0004
#        define F_SEAL_WRITE    0x0008

#        define F_ADD_SEALS 1033
#        define F_GET_SEALS 1034
#    endif /* F_SEAL_SEAL */

/**
 * Get an extended attribute in an allocated buffer
 */
static char *get_xattr_alloc(const char *path, const char *name)
{
    size_t bufsize;
    ssize_t returned_size;
    char *buffer;

    returned_size = getxattr(path, name, NULL, 0);
    if (returned_size < 0) {
        if (errno != ENODATA) {
            perror("getxattr");
        }
        return NULL;
    }
    bufsize = returned_size ? (size_t)returned_size : 1;
    buffer = malloc(bufsize);
    if (!buffer) {
        perror("malloc");
        return NULL;
    }
    returned_size = getxattr(path, name, buffer, bufsize);
    if (returned_size < 0) {
        perror("getxattr");
        free(buffer);
        return NULL;
    }
    if ((size_t)returned_size != bufsize) {
        fprintf(stderr, "getxattr(%s, %s) error: unexpected return size %lu instead of %lu\n",
                path, name, (unsigned long)returned_size, (unsigned long)bufsize);
        free(buffer);
        return NULL;
    }
    return buffer;
}

/**
 * Print the extended attributes of a file
 */
static void print_xattrs(const char *filepath)
{
    size_t bufsize;
    ssize_t returned_size;
    char *buffer, *name, *value;
    bool seen_security_acl = false;
    bool seen_security_capability = false;
    bool seen_security_selinux = false;

    returned_size = listxattr(filepath, NULL, 0);
    if (returned_size < 0) {
        perror("listxattr");
        return;
    }

    if (returned_size > 0) {
        bufsize = (size_t)returned_size;
        buffer = malloc(bufsize);
        if (!buffer) {
            perror("malloc");
            return;
        }
        returned_size = listxattr(filepath, buffer, bufsize);
        if (returned_size < 0) {
            perror("listxattr");
            free(buffer);
            return;
        }
        if ((size_t)returned_size != bufsize) {
            fprintf(stderr, "listxattr(%s) error: unexpected return size %lu instead of %lu\n",
                    filepath, (unsigned long)returned_size, (unsigned long)bufsize);
            free(buffer);
            return;
        }
        for (name = buffer; *name; name += strlen(name) + 1) {
            value = get_xattr_alloc(filepath, name);
            printf("  * %s = %s\n", name, value);
            free(value);
            if (!strcmp(name, "security.acl")) {
                seen_security_acl = true;
            } else if (!strcmp(name, "security.capability")) {
                seen_security_capability = true;
            } else if (!strcmp(name, "security.selinux")) {
                seen_security_selinux = true;
            }
        }

        free(buffer);
    } else {
        printf("  * (none listed)\n");
    }
    if (!seen_security_acl) {
        value = get_xattr_alloc(filepath, "security.acl");
        if (value) {
            printf("  * (unlisted) security.acl = %s\n", value);
            free(value);
        }
    }
    if (!seen_security_capability) {
        value = get_xattr_alloc(filepath, "security.capability");
        if (value) {
            printf("  * (unlisted) security.capability = %s\n", value);
            free(value);
        }
    }
    if (!seen_security_selinux) {
        value = get_xattr_alloc(filepath, "security.selinux");
        if (value) {
            printf("  * (unlisted) security.selinux = %s\n", value);
            free(value);
        }
    }
}

static bool test_memfd(void)
{
    int fd, current_seals;
    ssize_t bytes_written, bytes_read;
    size_t ubytes_written, ubytes_read;
    static const char memfd_content[] = "Hello, this is sealed!\n";
    char fd_link_path[256], buffer[256];
    struct stat sb;
    FILE *f;

    fd = memfd_create("my-memfd", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) {
        if (errno == ENOSYS) {
            /* Qemu-user does not support memfd_create */
            printf("Exit because the kernel does not support memfd_create.\n");
            exit(0);
        }
        perror("memfd_create");
        return false;
    }

    /* Write some content to a memfd */
    bytes_written = write(fd, memfd_content, sizeof(memfd_content));
    if (bytes_written < 0) {
        perror("write");
        close(fd);
        return false;
    } else if (bytes_written != sizeof(memfd_content)) {
        fprintf(stderr, "Error while writing memfd content: %lu/%lu bytes written\n",
                (unsigned long)bytes_written, (unsigned long)sizeof(memfd_content));
        close(fd);
        return false;
    }

    /* Seal the memfd */
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) == -1) {
        perror("fcntl(F_ADD_SEALS)");
        close(fd);
        return false;
    }

    /* Try writing to the memfd */
    bytes_written = write(fd, memfd_content, 1);
    if (bytes_written != -1) {
        fprintf(stderr, "Error: successful write to a sealed memfd (%lu byte)\n",
                (unsigned long)bytes_written);
        close(fd);
        return false;
    } else if (errno != EPERM) {
        fprintf(stderr, "Unexpected error when writing to a sealed memfd: %d (%s)\n",
                errno, strerror(errno));
        close(fd);
        return false;
    }

    current_seals = fcntl(fd, F_GET_SEALS);
    if (current_seals == -1) {
        perror("fcntl(F_GET_SEALS)");
        close(fd);
        return false;
    }
    printf("memfd's seals: %#x:\n", current_seals); /* 0xf */
    printf("  * F_SEAL_SEAL = %#x\n", F_SEAL_SEAL); /* 1 */
    printf("  * F_SEAL_SHRINK = %#x\n", F_SEAL_SHRINK); /* 2 */
    printf("  * F_SEAL_GROW = %#x\n", F_SEAL_GROW); /* 4 */
    printf("  * F_SEAL_WRITE = %#x\n", F_SEAL_WRITE); /* 8 */
    if (current_seals != 0xf) {
        fprintf(stderr, "Unexpected current seals: %#x != 0xf\n", current_seals);
        close(fd);
        return false;
    }

    snprintf(fd_link_path, sizeof(fd_link_path), "/proc/self/fd/%d", fd);
    bytes_read = readlink(fd_link_path, buffer, sizeof(buffer) - 1);
    if (bytes_read < 0) {
        perror("readlink(/proc/self/fd/{memfd})");
        close(fd);
        return false;
    }
    buffer[bytes_read] = '\0';
    printf("File descriptor %d is: %s\n", fd, buffer);

    memset(&sb, 0, sizeof(sb));
    if (stat(fd_link_path, &sb) == -1) {
        perror("stat(/proc/self/fd/{memfd})");
        close(fd);
        return false;
    }
    printf("stat():\n");
    printf("  * dev: %#" PRIx64 "\n", sb.st_dev); /* 5 on a normal system, where 4 is /proc and 6 is /dev in /proc/1/mountinfo */
    printf("  * ino: %#lx\n", sb.st_ino);
    printf("  * mode: 0o%o (S_IFREG = 0o%o)\n", sb.st_mode, S_IFREG);
    printf("  * uid: %u\n", sb.st_uid);
    printf("  * gid: %u\n", sb.st_gid);
    printf("  * size: %lu bytes (expected %lu)\n", sb.st_size, (unsigned long)sizeof(memfd_content));

    printf("xattrs:\n");
    print_xattrs(fd_link_path);

    /* Re-open the sealed memfd in order to try the restrictions */
    f = fopen(fd_link_path, "r+be");
    if (!f) {
        perror("fopen(/proc/self/fd/{memfd})");
        close(fd);
        return false;
    }
    close(fd);

    /* Disable any buffering */
    setvbuf(f, NULL, _IONBF, 0);

    ubytes_written = fwrite("\n", 1, 1, f);
    if (ubytes_written != 0) {
        fprintf(stderr, "Error successful write to a sealed memfd (%lu byte)\n",
                (unsigned long)ubytes_written);
        fclose(f);
        return false;
    } else if (errno != EPERM) {
        fprintf(stderr, "Unexpected error when writing to a sealed memfd: %d (%s)\n",
                errno, strerror(errno));
        fclose(f);
        return false;
    }

    ubytes_read = fread(buffer, 1, sizeof(buffer), f);
    if (!ubytes_read) {
        perror("fread");
        fclose(f);
        return false;
    } else if (ubytes_read != sizeof(memfd_content)) {
        fprintf(stderr, "Error while reading memfd content: %lu/%lu bytes\n",
                (unsigned long)ubytes_read, (unsigned long)sizeof(memfd_content));
        fclose(f);
        return false;
    } else if (strcmp(buffer, memfd_content)) {
        fprintf(stderr, "Unexpected modified data has been read: %s\n", buffer);
        fclose(f);
        return false;
    }
    printf("Successfully read the sealed data from %s\n", fd_link_path);

    fclose(f);
    return true;
}

/**
 * Re-start the program from a sealed file descriptor, like the fix for CVE-2019-5736:
 * https://github.com/opencontainers/runc/commit/0a8e4117e7f715d5fbeef398405813ce8e88558b
 */
static void reexec_sealed(void)
{
    int memfd, binfd;
    size_t total_written;
    ssize_t sent;
    struct stat sb;
    const char *new_argv[] = { "-", "--check-sealed", NULL };

    memfd = memfd_create("myself", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (memfd < 0) {
        perror("memfd_create");
        return;
    }

    printf("Copying /proc/self/exe to file descriptor %d...\n", memfd);
    binfd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (binfd < 0) {
        perror("open(/proc/self/exe)");
        close(memfd);
        return;
    }
    memset(&sb, 0, sizeof(sb));
    if (fstat(binfd, &sb) == -1) {
        perror("fstat(/proc/self/exe})");
        close(memfd);
        return;
    }
    for (total_written = 0; total_written < (size_t)sb.st_size; total_written += (size_t)sent) {
        sent = sendfile(memfd, binfd, NULL, ((size_t)sb.st_size) - total_written);
        if (sent < 0) {
            perror("sendfile");
            close(binfd);
            close(memfd);
            return;
        }
    }
    close(binfd);

    if (fcntl(memfd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) == -1) {
        perror("fcntl(F_ADD_SEALS)");
        close(memfd);
        return;
    }

    printf("Executing sealed file descriptor %d...\n", memfd);
    /* work around clang's -Wcast-qual warning */
    fexecve(memfd, (char **)(uintptr_t)new_argv, environ);
    perror("fexecve");
    close(memfd);
}

int main(int argc, char **argv)
{
    int fd, current_seals;
    ssize_t bytes_read;
    char exe_link_target[1024];

    /* Verify whether the program is being run as a sealed executable */
    if (argc == 2 && !strcmp(argv[1], "--check-sealed")) {
        fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            perror("open(/proc/self/exe)");
            return 1;
        }
        current_seals = fcntl(fd, F_GET_SEALS);
        if (current_seals == -1) {
            if (errno == EINVAL) {
                printf("/proc/self/exe cannot be sealed.\n");
            } else {
                perror("fcntl(F_GET_SEALS)");
            }
            close(fd);
            return 1;
        }
        if (current_seals != (F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)) {
            printf("/proc/self/exe does not have all the seals: %#x\n", current_seals);
            close(fd);
            return 1;
        }

        bytes_read = readlink("/proc/self/exe", exe_link_target, sizeof(exe_link_target) - 1);
        if (bytes_read < 0) {
            perror("readlink(/proc/self/exe)");
            close(fd);
            return 1;
        }
        exe_link_target[bytes_read] = '\0';
        printf("/proc/self/exe (%s) appears to be sealed :)\n", exe_link_target);
        return 0;
    }

    if (!test_memfd())
        return 1;

    reexec_sealed();
    /* re-execution failed */
    return 1;
}

#else /* __NR_memfd_create */

int main(void)
{
    printf("__NR_memfd_create is not defined, skipping test.\n");
    return 0;
}

#endif /* __NR_memfd_create */
