/**
 * Spawn a shell using C code and Linux ABI
 */
#include "nolibc-syscall-linux.h"

void _start(void)
{
    char shell[] = "/bin/sh", *argv[2];
    int ret;

    argv[0] = shell;
    argv[1] = 0;
    ret = execve(shell, argv, 0);
    exit(-ret);
}
