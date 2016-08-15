/**
 * Enumerate directories from the root to the current working directory
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for name_to_handle_at */
#endif

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * Return an allocated buffer containing the current working directory
 */
static char *getcwd_a(void)
{
    long lsize;
    size_t size;
    char *buffer, *ptr;
    /* From http://pubs.opengroup.org/onlinepubs/009695399/functions/getcwd.html */
    lsize = pathconf(".", _PC_PATH_MAX);
    assert(lsize > 0);
    size = (size_t)lsize;
    buffer = malloc(size);
    assert(buffer);
    ptr = getcwd(buffer, size);
    if (!ptr) {
        perror("getcwd");
        exit(EXIT_FAILURE);
    }
    assert(ptr == buffer);
    return buffer;
}

int main(void)
{
    char *wd;
    const char *path_part = NULL;
    int dir_fd = -1, retval = 1;
    bool is_not_end = true;

    wd = getcwd_a();

    /* Open the root directory */
    if (wd[0] != '/') {
        fprintf(stderr, "The current working directory does not start with '/': %s\n", wd);
        fprintf(stderr, "Your system is not yet supported :(\n");
        return 1;
    }
    /* Enumerate every subdirectory */
    do {
        char *path_end;
        struct stat st;
        int new_dirfd;
        DIR *dir = NULL;
        struct dirent *entry;

        /* Start with the root directory */
        if (!path_part) {
            path_part = "/";
            path_end = wd;
            dir_fd = AT_FDCWD;
            is_not_end = (wd[1] != '\0');
            printf("/\n");
        } else {
            path_end = strchrnul(path_part, '/');
            if (path_end == path_part) {
                path_part += 1;
                continue;
            }
            is_not_end = (*path_end == '/');
            *path_end = '\0';
            printf("\n%s/\n", path_part);
        }

        /* Stat the subdirectory */
        if (fstatat(dir_fd, path_part, &st, 0) == -1) {
            perror("fstatat");
            goto cleanup;
        }
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "A component in the working directory is not a directory\n");
            goto cleanup;
        }
        printf("  device %" PRIu64 " inode %ld (0x%08lx)\n", st.st_dev, st.st_ino, st.st_ino);

        /* Find the entry in the directory enumeration */
        if (dir_fd != AT_FDCWD) {
            dir = fdopendir(dir_fd);
            while (true) {
                errno = 0;
                entry = readdir(dir);
                if (!entry) {
                    if (errno) {
                        perror("readdir");
                        goto cleanup;
                    }
                    printf("... not found in parent directory :(\n");
                    break;
                }
                if (!strcmp(entry->d_name, path_part)) {
                    if (entry->d_ino != st.st_ino) {
                        /* direntry inode number of mountpoints comes from the parent filesystem,
                         * and stat inode number comes from the mounted filesystem. */
                        printf("  dir entry inode: %ld (0x%08lx)\n", entry->d_ino, entry->d_ino);
                    }
                    assert(entry->d_type == DT_DIR || entry->d_type == DT_UNKNOWN);
                    break;
                }
            }
        }
#if defined(__linux__) && defined(MAX_HANDLE_SZ)
        /* Use name_to_handle_at */
        {
            int mount_id = 0;
            unsigned int i;
            /* Force fh_buffer memory to be aligned on an integer boundary */
            int fh_buffer[(sizeof(struct file_handle) + MAX_HANDLE_SZ + sizeof(int) - 1) / sizeof(int)];
            struct file_handle *fhp = (struct file_handle *)fh_buffer;
            fhp->handle_bytes = MAX_HANDLE_SZ;
            if (name_to_handle_at(dir_fd, path_part, fhp, &mount_id, 0) == -1) {
                if (errno == ENOTSUP) {
                    printf("  (name_to_handle_at not supported here)\n");
                } else {
                    perror("name_to_handle_at");
                }
                /* This error is not fatal */
            } else {
                printf("  mount id %d\n", mount_id);
                printf("  handle type %d size %u:", fhp->handle_type, fhp->handle_bytes);
                assert(fhp->handle_bytes <= MAX_HANDLE_SZ);
                for (i = 0; i < fhp->handle_bytes; i++) {
                    printf(" %02x", fhp->f_handle[i]);
                }
                printf("\n");
            }
        }
#endif

        /* Open the subdirectory */
        new_dirfd = openat(dir_fd, path_part, O_RDONLY | O_CLOEXEC);
        if (new_dirfd == -1) {
            perror("openat");
            goto cleanup;
        }
        if (dir) {
            closedir(dir);
        } else if (dir_fd != AT_FDCWD) {
            close(dir_fd);
        }
        dir = NULL;
        dir_fd = new_dirfd;
        path_part = path_end + 1;
    } while (is_not_end);
    retval = 0;
cleanup:
    if (dir_fd >= 0) {
        close(dir_fd);
    }
    if (wd != NULL) {
        free(wd);
    }
    return retval;
}
