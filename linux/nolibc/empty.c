/**
 * Exit with value zero, which means OK
 */
#include "nolibc-syscall-linux.h"

void _start(void)
{
    exit(0);
}
