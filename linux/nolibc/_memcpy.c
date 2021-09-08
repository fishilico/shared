/**
 * Some compilers (such as "clang -m32" on x86) insert unexpected calls to memcpy.
 * So implement this function in a naive way
 */
#include <stdint.h>
#include <string.h>

void *memcpy(void *dst, const void *src, size_t size)
{
    uint8_t *d = dst;
    const uint8_t *s = src;

    for (; size > 0; size--) {
        *d++ = *s++;
    }
    return dst;
}
