/**
 * This program prints "Hello, world!" to the standard output
 */
#include "nolibc-syscall-linux.h"

void _start(void)
{
    int ret;
    const char helloworld[] = "Hello, world!\n";
    ret = write_all(1, helloworld, sizeof(helloworld));
    exit(ret ? 0 : 1);
}
