/**
 * Spawn a shell in a new process, using C code and Linux ABI
 */
#include "nolibc-syscall-linux.h"

void _start(void)
{
    char shell[] = "/bin/sh", *argv[2];
    int ret;

    ret = fork();
    if (ret != 0) {
        wait4(ret, NULL, 0, NULL);
        exit(0);
    }

    argv[0] = shell;
    argv[1] = 0;
    ret = execve(shell, argv, 0);
    exit(-ret);
}
