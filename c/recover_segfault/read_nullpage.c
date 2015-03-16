/**
 * Print content (apparently) from the null page
 */
#include "recover_segfault.h"

#include <stdint.h>
#include <stdio.h>

/* Use address from "1" to prevent printf from displaying (null).
 * x86_64 glibc strlen can read 16 bytes after the end of the string when using
 * SSE, and can also read a byte at address 0 because it is aligned.
 */
static char hello_null[] = "@Hello, world! Here is the pseudo-null page!"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

static int read_nullpage(void *data)
{
    printf("Address %p now contains: %s\n", data, (char *)data);
    return 0;
}

int main(void)
{
    struct segfault_memcontent memory;

    memory.addr = 0;
    memory.data = (uint8_t *)hello_null;
    memory.size = sizeof(hello_null);
    return run_with_segfault_handler(&memory, 1, read_nullpage, (void *)1);
}
