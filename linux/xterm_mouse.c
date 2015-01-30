/**
 * Use the mouse in a X11 terminal
 *
 * Some terminfo sequences:
 * * smcup   = \E[?1049h      enter alternate screen (enter_ca_mode)
 * * rmcup   = \E[?1049l      exit alternate screen (exit_ca_mode)
 * * cup 1 2 = \E[2;3H        set cursor pos to 2nd column, 3rd line (x=1, y=2)
 * * civis   = \E[?25l        make cursor invisible
 * * cnorm   = \E[?12l\E[?25h make cursor normal
 * * cvvis   = \E[?12;25h     make cursor very visible
 * * el      = \E[K           clear to end of line
 * * ed      = \E[J           clear to end to screen
 * * clear   = \E[H\E[2J      clear screen and home cursor
 * * XM 1    = \E[?1002h      enable "any event" mouse mode (xterm-1002)
 * * XM 0    = \E[?1002l      disable "any event" mouse mode (xterm-1002)
 * *           \E[?1006h      enable mouse protocol
 * *           \E[?1006l      disable mouse protocol
 *
 * Note: the escape sequences can be obtained with something like:
 *  strace -ewrite -o/proc/self/fd/3 -s500 tput -T$TERM smcup 3>&1 >/dev/null 2>&1
 *
 * Some documentation:
 * * terminfo sequences related to mouse are "XM" and "xm" in
 *   http://invisible-island.net/ncurses/terminfo.src.html
 * * ncurses implements a mouse interface in ncurses/base/lib_mouse.c:
 *   http://fossies.org/dox/ncurses-5.9/lib__mouse_8c_source.html
 * * ... the associated man page is curs_mouse(3x):
 *   http://www.manpagez.com/man/3/curs_mouse/
 */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

/**
 * Global variables
 */
static int tty_fd = -1;
static unsigned int win_cols;
static unsigned int win_rows;
static struct termios tty_attr_orig;

/**
 * Callback to update win_cols and win_rows according to the size of tty_fd
 */
static int update_winsize(void)
{
    struct winsize window_size;

    if (tty_fd < 0) {
        return 0;
    }
    if (ioctl(tty_fd, TIOCGWINSZ, &window_size) < 0) {
        perror("ioctl(tty, TIOCGWINSZ)");
        return 0;
    }
    win_cols = window_size.ws_col;
    win_rows = window_size.ws_row;
    return 1;
}

/**
 * Write every byte to the tty
 */
static int tty_write(const char *buffer, size_t count)
{
    if (tty_fd < 0) {
        return 0;
    }
    while (count > 0) {
        ssize_t ret = write(tty_fd, buffer, count);
        if (ret >= 0) {
            buffer += ret;
            count -= (size_t)ret;
        } else if (errno != EINTR) {
            perror("write(tty)");
            return 0;
        }
    }
    return 1;
}
static int tty_print(const char *string)
{
    return tty_write(string, strlen(string));
}

/**
 * Initialize the tty
 */
static int tty_init(void)
{
    const char *tty_name = "/dev/tty";
    struct termios tty_attr;

    /* Open a RW file descriptor to the current tty, using stdout or /dev/tty */
    if (isatty(STDOUT_FILENO)) {
        tty_name = ttyname(STDOUT_FILENO);
        if (!tty_name) {
            perror("ttyname");
            return 0;
        }
    }

    tty_fd = open(tty_name, O_RDWR | O_CLOEXEC);
    if (tty_fd == -1) {
        perror("open(tty)");
        return 0;
    }

    /* Setup terminal attributes */
    if (tcgetattr(tty_fd, &tty_attr) == -1) {
        perror("tcgetattr");
        close(tty_fd);
        tty_fd = -1;
        return 0;
    }
    tty_attr_orig = tty_attr;
    tty_attr.c_lflag &= ~(unsigned)ICANON;  /* Disable canonical mode */
    tty_attr.c_lflag &= ~(unsigned)ECHO;  /* Don't echo input characters */
    tty_attr.c_lflag |= ISIG;  /* Convert INT and QUIT chars to signal */
    if (tcsetattr(tty_fd, TCSAFLUSH, &tty_attr) == -1) {
        perror("tcsetattr");
        return 0;
    }

    /* Get the window size */
    if (!update_winsize()) {
        return 0;
    }

    /* Enter alternate screen, make cursor invisible and enable mouse protocol */
    if (!tty_print("\033[?1049h\033[?25l\033[?1002;1006h")) {
        return 0;
    }
    return 1;
}

/**
 * Revert everything tty_init did
 */
static void tty_reset(void)
{
    if (tty_fd == -1) {
        return;
    }
    /* Exit alternate screen, make cursor normal and disable mouse protocol */
    tty_print("\033[?1049l\033[?12l\033[?25h\033[?1002;1006l");

    /* Restore initial terminal attributes and drop unread input */
    if (tcsetattr(tty_fd, TCSAFLUSH, &tty_attr_orig) == -1) {
        perror("tcsetattr");
    }

    close(tty_fd);
    tty_fd = -1;
}

/**
 * Quit nicely when handling the interrupt signal
 */
static void __attribute__((noreturn)) handle_sigterm(int signum)
{
    assert(signum == SIGINT || signum == SIGQUIT || signum == SIGTERM);
    tty_reset();
    exit(0);
}

/**
 * Handle window change signal
 */
static void handle_sigwinch(int signum)
{
    assert(signum == SIGWINCH);
    update_winsize();
}

int main(void)
{
    struct sigaction sa;
    unsigned char buffer[1024];
    char textbuf[200];
    ssize_t count;
    size_t i, curpos, textbufpos;
    int saved_errno;
    unsigned int mouse_buttons, mouse_x, mouse_y;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = handle_sigterm;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction(SIGINT)");
        return 1;
    }
    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        perror("sigaction(SIGQUIT)");
        return 1;
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction(SIGTERM)");
        return 1;
    }
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = handle_sigwinch;
    if (sigaction(SIGWINCH, &sa, NULL) == -1) {
        perror("sigaction(SIGWINCH)");
        return 1;
    }

    if (!tty_init()) {
        tty_reset();
        return 1;
    }

    snprintf(textbuf, sizeof(textbuf),
             "Window size: %u x %u\n",
             win_cols, win_rows);
    tty_print(textbuf);

    curpos = 0;
    for (;;) {
        assert(curpos < sizeof(buffer));
        count = read(tty_fd, buffer + curpos, (size_t)(sizeof(buffer) - curpos));
        if (count == -1) {
            if (errno == EINTR) {
                /* display current window size */
                snprintf(textbuf, sizeof(textbuf),
                         "\033[HWindow size: %u x %u\033[K\n",
                         win_cols, win_rows);
                tty_print(textbuf);
                continue;
            }
            saved_errno = errno;
            tty_reset();
            errno = saved_errno;
            perror("read");
            return 1;
        }
        /* There are curpos+count available bytes in the buffer */
        count += curpos;
        curpos = 0;
        for (i = 0; i < (size_t)count; i++) {
            if (buffer[i] == '\003' || buffer[i] == 'q' || buffer[i] == 'Q') {
                /* Quit if Received ^C, q or Q from the terminal */
                tty_reset();
                return 0;
            } else if (buffer[i] == 'c' || buffer[i] == 'C') {
                /* Clear screen */
                tty_print("\033[H\033[2J");
                continue;
            } else if (buffer[i] != '\033') {
                /* Received something else than escape sequence, continue */
                continue;
            }
            /* Mouse is \e[M and 3 characters */
            if (i + 6 > (size_t)count) {
                /* The sequence has not been completely read, keep its beginning */
                curpos = ((size_t)count) - i;
                memmove(buffer, buffer + i, curpos);
                break;
            }
            if (buffer[i + 1] != '[' && buffer[i + 2] != 'M') {
                continue;
            }

            /* Retrieve mouse state from buffer */
            mouse_buttons = (unsigned int)(buffer[i + 3] - ' ');
            mouse_x = (unsigned int)(buffer[i + 4] - ' ' - 1) & 0xff;
            mouse_y = (unsigned int)(buffer[i + 5] - ' ' - 1) & 0xff;

            /* Display a pattern */
            textbuf[0] = '\0';

            /* Change the color depending on the button state */
            switch (mouse_buttons) {
                case 0:
                    /* Left button pressed */
                    snprintf(textbuf, sizeof(textbuf), "\033[31m");
                    break;
                case 1:
                    /* Middle button pressed */
                    snprintf(textbuf, sizeof(textbuf), "\033[32m");
                    break;
                case 2:
                    /* Right button pressed */
                    snprintf(textbuf, sizeof(textbuf), "\033[34m");
                    break;
                case 3:
                    /* Button released */
                    snprintf(textbuf, sizeof(textbuf), "\033[37m");
                    break;
                case 0x20:
                    /* Move with left button pressed */
                    snprintf(textbuf, sizeof(textbuf), "\033[41m");
                    break;
                case 0x21:
                    /* Move with middle button pressed */
                    snprintf(textbuf, sizeof(textbuf), "\033[42m");
                    break;
                case 0x22:
                    /* Move with right button pressed */
                    snprintf(textbuf, sizeof(textbuf), "\033[44m");
                    break;
                case 0x40:
                    /* Mouse wheel up */
                    snprintf(textbuf, sizeof(textbuf), "\033[43m");
                    break;
                case 0x41:
                    /* Mouse wheel down */
                    snprintf(textbuf, sizeof(textbuf), "\033[46m");
            }
            textbufpos = strlen(textbuf);

            /* Show a cross on cursor position */
            if (mouse_y >= 1) {
                snprintf(textbuf + textbufpos, sizeof(textbuf) - textbufpos,
                         "\033[%u;%uH|", mouse_y, mouse_x + 1);
                textbufpos += strlen(textbuf + textbufpos);
            }
            if (mouse_x == 0) {
                snprintf(textbuf + textbufpos, sizeof(textbuf) - textbufpos,
                         "\033[%u;1HX-", mouse_y + 1);
            } else if (mouse_x + 1 >= win_cols) {
                snprintf(textbuf + textbufpos, sizeof(textbuf) - textbufpos,
                         "\033[%u;%uH-X", mouse_y + 1, mouse_x);
            } else {
                snprintf(textbuf + textbufpos, sizeof(textbuf) - textbufpos,
                         "\033[%u;%uH-X-", mouse_y + 1, mouse_x);
            }
            textbufpos += strlen(textbuf + textbufpos);
            if (mouse_y + 1 < win_rows) {
                snprintf(textbuf + textbufpos, sizeof(textbuf) - textbufpos,
                         "\033[%u;%uH|", mouse_y + 2, mouse_x + 1);
                textbufpos += strlen(textbuf + textbufpos);
            }
            assert(textbufpos + 3 < sizeof(textbuf));
            snprintf(textbuf + textbufpos, sizeof(textbuf) - textbufpos, "\033[m");
            tty_print(textbuf);
            /* printf("\033[H0x%02x, %u, %u\033[K\n", mouse_buttons, mouse_x, mouse_y); */
            i += 5;
        }
    }
}
