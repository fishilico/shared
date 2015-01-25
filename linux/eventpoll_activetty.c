/**
 * Use eventpoll to record active TTY switch
 */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>

static bool read_active_tty(int active_tty_fd, bool is_changed)
{
    char buffer[1024];
    ssize_t bytes;
    size_t count;

    if (lseek(active_tty_fd, SEEK_SET, 0) == (off_t)-1) {
        perror("lseek");
        return false;
    }

    count = 0;
    do {
        bytes = read(active_tty_fd, buffer + count, sizeof(buffer) - 1 - count);
        if (bytes == -1) {
            perror("read(active tty)");
            return false;
        }
        assert(bytes >= 0);
        count += (size_t)bytes;
    } while (bytes && count < sizeof(buffer));
    if (count >= sizeof(buffer)) {
        fprintf(stderr, "Error: active tty file too big");
        return false;
    }
    while (count > 0 && buffer[count - 1] == '\n') {
        count--;
    }
    buffer[count] = '\0';

    if (!is_changed) {
        printf("Active TTY is %s\n", buffer);
    } else {
        printf("TTY switched to %s\n", buffer);
    }
    return true;
}

int main(void)
{
    int active_tty_fd, epollfd, i, nfds, retval;
    bool running;
    struct epoll_event ev, events[2];
    char buffer[4096];
    ssize_t bytes;

    /* Use unbuffered stdin */
    setvbuf(stdin, NULL, _IONBF, 0);

    active_tty_fd = open("/sys/class/tty/tty0/active", O_RDONLY | O_CLOEXEC);
    if (active_tty_fd == -1) {
        perror("open(/sys/class/tty/tty0/active)");
        return 1;
    }

    if (!read_active_tty(active_tty_fd, false)) {
        return 1;
    }

    /* If stdin is not a tty, stop here */
    if (!isatty(STDIN_FILENO)) {
        return 0;
    }

    /* Create a new epoll instance */
    epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (epollfd == -1) {
        perror("epoll_create1");
        close(active_tty_fd);
        return 1;
    }

    /* Add stdin to the epoll */
    ev.events = EPOLLIN;
    ev.data.fd = STDIN_FILENO;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) == -1) {
        perror("epoll_ctl(EPOLL_CTL_ADD, stdin)");
        close(active_tty_fd);
        close(epollfd);
        return 1;
    }

    /* Add the file descriptor to the epoll
     * Wait for EPOLLERR events, and epoll_ctl man page states that
     * "epoll_wait will always wait for this event;
     *  it is not necessary to set it in events."
     */
    ev.events = 0;
    ev.data.fd = active_tty_fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, active_tty_fd, &ev) == -1) {
        perror("epoll_ctl(EPOLL_CTL_ADD)");
        close(active_tty_fd);
        close(epollfd);
        return 1;
    }

    running = true;
    retval = 0;
    while (running) {
        nfds = epoll_wait(epollfd, events, sizeof(events) / sizeof(events[0]), -1);
        if (nfds == -1) {
            perror("epoll_pwait");
            retval = 1;
            break;
        }

        for (i = 0; i < nfds; i++) {
            if (events[i].data.fd == 0) {
                /* Consume stdin until EOF */
                bytes = read(STDIN_FILENO, buffer, sizeof(buffer));
                if (bytes == -1) {
                    if (errno == EINTR) {
                        /* Next iteration will consume the data */
                        continue;
                    }
                    perror("fread(stdin)");
                    retval = 1;
                    running = false;
                } else if (!bytes) {
                    running = false;
                } else {
                    printf("Eating some bytes from stdin...\n");
                }
            }
            if (events[i].data.fd == active_tty_fd) {
                if (!read_active_tty(active_tty_fd, true)) {
                    retval = 1;
                    running = false;
                }
            }
        }
    }

    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, active_tty_fd, &ev) == -1) {
        perror("epoll_ctl(EPOLL_CTL_DEL)");
        retval = 1;
    }
    close(active_tty_fd);

    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, STDIN_FILENO, &ev) == -1) {
        perror("epoll_ctl(EPOLL_CTL_DEL, stdin)");
        retval = 1;
    }
    close(epollfd);
    return retval;
}
