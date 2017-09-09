/**
 * Show some information using TTY ioctl
 *
 * Documentation:
 * * man tty_ioctl(4)
 *   http://man7.org/linux/man-pages/man4/tty_ioctl.4.html
 * * stty --all
 * * /usr/include/bits/termios.h for TTY flags
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for O_CLOEXEC */
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

/* Do not include linux/kd.h as it might not be available.  Use constants from
 * https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/kd.h
 */
#define KDGETLED 0x4B31
#define LED_SCR 0x01
#define LED_NUM 0x02
#define LED_CAP 0x04

static const char *tty_control_char_descs[] = {
    "VINTR", /* 0 */
    "VQUIT", /* 1 */
    "VERASE", /* 2 */
    "VKILL", /* 3 */
    "VEOF", /* 4 */
    "VTIME", /* 5 */
    "VMIN", /* 6 */
    "VSWTC", /* 7 */
    "VSTART", /* 8 */
    "VSTOP", /* 9 */
    "VSUSP", /* 10 */
    "VEOL", /* 11 */
    "VREPRINT", /* 12 */
    "VDISCARD", /* 13 */
    "VWERASE", /* 14 */
    "VLNEXT", /* 15 */
    "VEOL2", /* 16 */
};
#define NKNOWNCCS (sizeof(tty_control_char_descs) / sizeof(tty_control_char_descs[0]))

int main(void)
{
    int tty_fd, length = 0;
    unsigned int i, maxccs;
    struct winsize window_size;
    struct termios tty_attr;
    const char *cmd = "echo Hello world\n", *curbyte;
    char cc_desc[8], led_state = 0;

    /* Use stdin as TTY, if available, else /dev/tty */
    tty_fd = STDIN_FILENO;
    if (!isatty(tty_fd)) {
        tty_fd = open("/dev/tty", O_RDWR | O_CLOEXEC);
        if (tty_fd == -1) {
            if (errno == ENXIO) {
                printf("No TTY found, doing nothing.\n");
                return 0;
            }
            perror("open(/dev/tty)");
            return 1;
        }
    }

    /* Show the name of the TTY, which comes from /proc/self/fd symlink */
    printf("TTY name: %s\n", ttyname(tty_fd));

    memset(&window_size, 0, sizeof(window_size));
    if (ioctl(tty_fd, TIOCGWINSZ, &window_size) < 0) {
        perror("ioctl(tty, TIOCGWINSZ)");
        return 1;
    }
    printf("Window size: %u cols, %u rows, %ux%u pixels\n",
           window_size.ws_row, window_size.ws_col,
           window_size.ws_xpixel, window_size.ws_ypixel);

    memset(&tty_attr, 0, sizeof(tty_attr));
    if (ioctl(tty_fd, TCGETS, &tty_attr) < 0) {
        perror("ioctl(tty, TCGETS)");
        return 1;
    }
    printf("Terminal attributes:\n");
    printf("  Input mode flags: %#x\n", tty_attr.c_iflag);
    printf("  Output mode flags: %#x\n", tty_attr.c_oflag);
    printf("  Control mode flags: %#x\n", tty_attr.c_cflag);
    printf("  Local mode flags: %#x\n", tty_attr.c_lflag);
    printf("  Line discipline: %#x\n", tty_attr.c_line);
    /* Find the last defined control character */
    assert(sizeof(tty_attr.c_cc) == NCCS * sizeof(cc_t));
    for (maxccs = NCCS - 1; maxccs >= NKNOWNCCS; maxccs--) {
        if (tty_attr.c_cc[maxccs]) {
            break;
        }
    }
    printf("  Control characters (%u):\n", maxccs + 1);
    for (i = 0; i <= maxccs; i++) {
        if (tty_attr.c_cc[i] == 0) {
            strcpy(cc_desc, "<undef>");
        } else if (tty_attr.c_cc[i] < 32) {
            sprintf(cc_desc, "^%c", tty_attr.c_cc[i] + 64);
        } else if (tty_attr.c_cc[i] < 127) {
            sprintf(cc_desc, "%c", tty_attr.c_cc[i]);
        } else if (tty_attr.c_cc[i] == 127) {
            strcpy(cc_desc, "^?");
        } else {
            sprintf(cc_desc, "\\x%02x", tty_attr.c_cc[i]);
        }

        if (i < NKNOWNCCS) {
            printf("    %-8s: %s\n", tty_control_char_descs[i], cc_desc);
        } else {
            printf("    %-8u: %s\n", i, cc_desc);
        }
    }

    /* Linux console-specific command */
    if (ioctl(tty_fd, KDGETLED, &led_state) == -1) {
        if (errno == ENOTTY || errno == EINVAL) {
            /* TTY is not Linux console */
            printf("Unable to get the state of keyboard LEDs\n");
        } else {
            perror("ioctl(tty, KDGETLED)");
            return 1;
        }
    } else {
        printf("Keyboard LED state %#x = %cCAP %cNUM %cSCR\n", led_state,
               (led_state & LED_CAP) ? '+' : '-',
               (led_state & LED_NUM) ? '+' : '-',
               (led_state & LED_SCR) ? '+' : '-');
    }

    /* Put the command to the TTY input buffer */
    printf("Injecting '%.*s' to the TTY.\n", (int)(strlen(cmd) - 1), cmd);
    for (curbyte = cmd; *curbyte; curbyte++) {
        if (ioctl(tty_fd, TIOCSTI, curbyte)) {
            perror("ioctl(tty, TIOCSTI)");
            /* Non-fatal error */
            break;
        }
    }

    /* Read back from the TTY */
    if (ioctl(tty_fd, TIOCINQ, &length) == -1) {
        perror("ioctl(tty, TIOCINQ)");
        return 1;
    }
    printf("Flushing %d bytes from the TTY input.\n", length);
    if (ioctl(tty_fd, TCFLSH, TCIFLUSH) == -1) {
        perror("ioctl(tty, TCFLSH)");
        return 1;
    }
    if (ioctl(tty_fd, TIOCINQ, &length) == -1) {
        perror("ioctl(tty, TIOCINQ)");
        return 1;
    }
    if (length) {
        printf("Ugh, %d characters remained in the TTY input after flushing!\n", length);
    }

    /* Clean up */
    if (tty_fd != STDIN_FILENO) {
        close(tty_fd);
    }
    return 0;
}
