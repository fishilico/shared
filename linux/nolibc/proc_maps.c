/**
 * Dump self memory mappings (/proc/self/maps)
 */
#include "nolibc-syscall-linux.h"

void _start(void)
{
    char buffer[4096];
    int fd;
    ssize_t rdlen;
    char proc_self_maps[] = "/proc/self/maps";

    fd = open2(proc_self_maps, O_RDONLY);
    if (fd < 0) {
        write_cstring_using_stack(2, "Error: unable to open /proc/self/maps\n");
        exit(1);
    }
    while ((rdlen = read_buffer(fd, buffer, sizeof(buffer))) > 0) {
        if (!write_all(1, buffer, (size_t)rdlen)) {
            write_cstring_using_stack(2, "Error: failed writing to the standard output\n");
            close(fd);
            exit(1);
        }
    }
    close(fd);
    if (rdlen < 0) {
        write_cstring_using_stack(2, "Error: failed reading /proc/self/maps\n");
        exit(1);
    }
    exit(0);
}
