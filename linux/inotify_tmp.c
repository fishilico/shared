/**
 * Monitor inotify events for /tmp directory
 *
 * This is quite similar to "busybox inotifyd - /tmp", from:
 * https://git.busybox.net/busybox/tree/miscutils/inotifyd.c
 * Or "inotifywait -m --timefmt '%H:%M:%S' --format '%T %w %e %f' /tmp"
 * from inotify-tools (https://github.com/inotify-tools/inotify-tools)
 */
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

/* IN_EXCL_UNLINK has been introduced in Linux 2.6.36, glibc 2.13 */
#if defined(__GNU_LIBRARY__) && ((__GLIBC__ << 16) + __GLIBC_MINOR__ < 0x2000d)
#    ifndef IN_EXCL_UNLINK
#        define IN_EXCL_UNLINK 0
#    endif
#endif

int main(void)
{
    int notifyfd, wd, length;
    uint8_t *buffer;
    char *name, timebuf[1024];
    ssize_t bytes;
    size_t i;
    struct inotify_event event;
    uint32_t mask;
    time_t now;

    notifyfd = inotify_init1(IN_CLOEXEC);
    if (notifyfd == -1) {
        perror("inotify_init1");
        return 1;
    }

    /* Don't watch deleted files in /tmp because it can be incredibly verbose */
    wd = inotify_add_watch(notifyfd, "/tmp", IN_ALL_EVENTS | IN_EXCL_UNLINK);
    if (wd == -1) {
        perror("inotify_add_watch");
        return 1;
    }

    printf("Watching /tmp events...\n");
    for (;;) {
        /* Block until bytes are available */
        bytes = read(notifyfd, NULL, 0);
        assert(bytes == -1);
        if (errno == EINTR) {
            printf("read() has been interrupted by a signal. Exiting.\n");
            break;
        } else if (errno != EINVAL) {
            perror("read");
            return 1;
        }

        /* Record time */
        now = time(0);
        if (now == ((time_t)-1)) {
            perror("time");
            return 1;
        }
        if (!strftime(timebuf, sizeof(timebuf), "%H:%M:%S", localtime(&now))) {
            assert(sizeof(timebuf) >= sizeof("[strftime error]"));
            strcpy(timebuf, "[strftime error]");
        }
        timebuf[sizeof(timebuf) - 1] = '\0';

        /* Get the readable length */
        length = 0;
        if (ioctl(notifyfd, FIONREAD, &length) == -1) {
            perror("ioctl(FIONREAD)");
            return 1;
        }
        if (!length) {
            fprintf(stderr, "No byte available from the notifyfd!?\n");
            return 1;
        }
        assert(length > 0);

        /* Read all the available events */
        buffer = malloc((size_t)length);
        assert(buffer);
        bytes = read(notifyfd, buffer, (size_t)length);
        if (bytes == -1) {
            if (errno == EINTR) {
                printf("read() has been interrupted by a signal. Exiting.\n");
                free(buffer);
                break;
            } else {
                perror("read");
                free(buffer);
                return 1;
            }
        }
        assert((size_t)bytes == (size_t)length);
        for (i = 0; i < (size_t)bytes; i += sizeof(struct inotify_event) + event.len) {
            assert(i + sizeof(struct inotify_event) <= (size_t)bytes);
            memcpy(&event, buffer + i, sizeof(struct inotify_event));
            name = (char *)(buffer + i + sizeof(struct inotify_event));
            assert(i + sizeof(struct inotify_event) + event.len <= (size_t)bytes);
            assert(event.wd == wd);

            printf("%s ", timebuf);
            if (event.len) {
                assert(name[event.len - 1] == '\0');
                printf("/tmp/%s", name);
            } else {
                printf("/tmp");
            }
            printf(":");

            mask = event.mask;
#define print_event_mask(maskname) \
    do { \
        if (event.mask & IN_##maskname) { \
            printf(" " #maskname); \
        } \
        mask &= (uint32_t)~IN_##maskname; \
    } while (0)
            print_event_mask(ACCESS);
            print_event_mask(MODIFY);
            print_event_mask(ATTRIB);
            print_event_mask(CLOSE_WRITE);
            print_event_mask(CLOSE_NOWRITE);
            print_event_mask(OPEN);
            print_event_mask(MOVED_FROM);
            print_event_mask(MOVED_TO);
            print_event_mask(CREATE);
            print_event_mask(DELETE);
            print_event_mask(DELETE_SELF);
            print_event_mask(MOVE_SELF);
            print_event_mask(UNMOUNT);
            print_event_mask(Q_OVERFLOW);
            print_event_mask(IGNORED);
            print_event_mask(ISDIR);
            print_event_mask(ONESHOT);
#undef print_event_mask
            /* Print remaining unknown bits from mask */
            if (mask) {
                printf(" 0x%x", mask);
            }

            if (event.cookie) {
                printf(" (cookie = 0x%x)", event.cookie);
            }
            printf("\n");
        }
        free(buffer);
    }

    printf("Stopping watching /tmp events.\n");

    if (inotify_rm_watch(notifyfd, wd) == -1) {
        perror("inotify_rm_watch");
        return 1;
    }
    close(notifyfd);
    return 0;
}
