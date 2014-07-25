/**
 * Enumerate directories from the root to the current working directory
 */
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
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
    size_t size;
    char *buffer, *ptr;
    /* From http://pubs.opengroup.org/onlinepubs/009695399/functions/getcwd.html */
    size = pathconf(".", _PC_PATH_MAX);
    assert(size > 0);
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

int main()
{
    char *wd;
    const char *path_part;
    int dirfd, retval = 1;
    bool is_not_end;

    wd = getcwd_a();

    /* Open the root directory */
    if (wd[0] != '/') {
        fprintf(stderr, "The current working directory does not start with '/': %s\n", wd);
        fprintf(stderr, "Your system is not yet supported :(\n");
        return 1;
    }
    /* Enumerate every subdirectory */
    path_part = NULL;
    do {
        char *path_end;
        struct stat st;
        int new_dirfd;
        DIR *dir = NULL;
        struct dirent entry_buffer, *entry;

        /* Start with the root directory */
        if (!path_part) {
            path_part = "/";
            path_end = wd;
            dirfd = AT_FDCWD;
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
        if (fstatat(dirfd, path_part, &st, 0) == -1) {
            perror("fstatat");
            goto cleanup;
        }
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "A component in the working directory is not a directory\n");
            goto cleanup;
        }
        printf("  device %"PRIu64" inode %ld (0x%08lx)\n", st.st_dev, st.st_ino, st.st_ino);

        /* Find the entry in the directory enumeration */
        if (dirfd != AT_FDCWD) {
            dir = fdopendir(dirfd);
            while (true) {
                if (readdir_r(dir, &entry_buffer, &entry) == -1) {
                    perror("readdir");
                    goto cleanup;
                }
                if (!entry) {
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

#if defined(__linux__) && defined(_GNU_SOURCE) && defined(MAX_HANDLE_SZ)
        /* Use name_to_handle_at */
        {
            int mount_id = 0;
            unsigned int i;
            char fh_buffer[sizeof(struct file_handle) + MAX_HANDLE_SZ];
            struct file_handle *fhp = (struct file_handle*)fh_buffer;
            fhp->handle_bytes = MAX_HANDLE_SZ;
            if (name_to_handle_at(dirfd, path_part, fhp, &mount_id, 0) == -1) {
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
        new_dirfd = openat(dirfd, path_part, O_RDONLY | O_CLOEXEC);
        if (new_dirfd == -1) {
            perror("openat");
            goto cleanup;
        }
        if (dir) {
            closedir(dir);
        } else if (dirfd != AT_FDCWD) {
            close(dirfd);
        }
        dir = NULL;
        dirfd = new_dirfd;
        path_part = path_end + 1;
    } while (is_not_end);
    retval = 0;
cleanup:
    if (dirfd >= 0) {
        close(dirfd);
    }
    if (wd != NULL) {
        free(wd);
    }
    return retval;
}
