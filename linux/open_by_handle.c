/**
 * Open a file using the "handle" Linux API
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for name_to_handle_at, open_by_handle_at */
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* When name_to_handle_at is not supported, MAX_HANDLE_SZ is unlikely to be defined */
#ifdef MAX_HANDLE_SZ
static bool same_content(int fd1, int fd2)
{
    char buffer1[4096], buffer2[4096];
    ssize_t size1, size2;

    assert(sizeof(buffer1) == sizeof(buffer2));
    do {
        do {
            size1 = read(fd1, buffer1, sizeof(buffer1));
        } while (size1 == -1 && errno == EINTR);
        if (size1 == -1) {
            perror("read");
            return false;
        }

        do {
            size2 = read(fd2, buffer2, sizeof(buffer2));
        } while (size2 == -1 && errno == EINTR);
        if (size2 == -1) {
            perror("read");
            return false;
        }

        if (size1 != size2 || memcmp(buffer1, buffer2, (size_t)size1)) {
            return false;
        }
    } while (size1 > 0 && size2 > 0);
    return true;
}

static bool test_open_by_handle_with_name(const char *pathname, bool is_file)
{
    /* Align buffer with the alignment required for struct file_handle */
    int fh_buffer[(sizeof(struct file_handle) + MAX_HANDLE_SZ + sizeof(int) - 1) / sizeof(int)];
    unsigned int fh_allocated = MAX_HANDLE_SZ;
    struct file_handle *fhp = (struct file_handle *)fh_buffer;
    int mount_id = 0, fd_ref, fd;
    unsigned int i;
    bool result;

    fhp->handle_bytes = fh_allocated;
    if (name_to_handle_at(AT_FDCWD, pathname, fhp, &mount_id, 0) == -1) {
        if (errno == ENOSYS) {
            fprintf(stderr, "Exit because the kernel does not support name_to_handle_at.\n");
            exit(0);
        } else if (errno == EPERM) {
            /* Docker filters this syscall in its default seccomp policy */
            fprintf(stderr, "Exit because calls to name_to_handle_at are denied.\n");
            exit(0);
        } else if (errno == ENOENT) {
            printf("%s does not exist\n", pathname);
            return true;
        } else if (errno == ENOTSUP) {
            /* For example in containers using overlay filesystem do not implement "fh_to_dentry" */
            printf("%s does not support name_to_handle_at\n", pathname);
            return true;
        }
        perror("name_to_handle_at");
        return false;
    }

    printf("%s: mount %d type %d size %u:", pathname, mount_id, fhp->handle_type, fhp->handle_bytes);
    assert(fhp->handle_bytes <= fh_allocated);
    for (i = 0; i < fhp->handle_bytes; i++) {
        printf(" %02x", fhp->f_handle[i]);
    }
    printf("\n");

    /* Use open() directly to get a reference to the mounted filesystem */
    fd_ref = open(pathname, O_RDONLY);
    if (fd_ref == -1) {
        perror("open");
        return false;
    }

    fd = open_by_handle_at(fd_ref, fhp, O_RDONLY);
    if (fd == -1) {
        if (errno == EPERM) {
            printf("... open_by_handle_at denied. Need CAP_DAC_READ_SEARCH capability.\n");
            close(fd_ref);
            return true;
        }
        perror("open_by_handle_at");
        close(fd_ref);
        return false;
    }

    /* Check that data read from both file descriptors is the same */
    result = true;
    if (is_file && !same_content(fd, fd_ref)) {
        fprintf(stderr, "Different data has been read from %s with open and open_by_handle_at!\n", pathname);
        result = false;
    }
    close(fd);
    close(fd_ref);
    return result;
}

int main(void)
{
    if (!test_open_by_handle_with_name("/", false))
        return 1;
    if (!test_open_by_handle_with_name("/dev", false))
        return 1;
    if (!test_open_by_handle_with_name("/tmp", false))
        return 1;
    if (!test_open_by_handle_with_name("/etc/hostname", true))
        return 1;
    return 0;
}
#else /* MAX_HANDLE_SZ */
int main(void)
{
    printf("name_to_handle_at and open_by_handle_at seem to be unsupported by your libc.\n");
    /* Return success so that "make test" doesn't fail with a libc like musl */
    return 0;
}
#endif /* MAX_HANDLE_SZ */
