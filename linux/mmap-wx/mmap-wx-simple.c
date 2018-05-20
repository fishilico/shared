/**
 * mmap-wx-simple.c
 *
 * Simpler version of mmap-wx.c
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for MAP_ANONYMOUS, ftruncate, mkstemp */
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

__attribute__ ((noreturn))
static void perror_exit(const char *s)
{
    perror(s);
    exit(1);
}

int main(void)
{
    const char template[] = "./mmap-wx-XXXXXX";
#if defined(__i386__) || defined(__x86_64__)
    const uint8_t code[] = { 0x31, 0xc0, 0xc3 };
#elif defined(__arm__)
    const uint32_t code[] = { 0xe3a00000, 0xe12fff1e };
#elif defined(__aarch64__)
    const uint32_t code[] = { 0xd2800000, 0xd65f03c0 };
#else
#    error Unsupported architecture
#endif
    char filename[4096];
    int fd, result;
    void *wptr, *xptr;

    memcpy(filename, template, sizeof(template));
    fd = mkstemp(filename);
    if (fd == -1)
        perror_exit("mkstemp");
    if (unlink(filename) < 0)
        perror_exit("unlink");
    if (ftruncate(fd, sizeof(code)) < 0)
        perror_exit("ftruncate");
    wptr = mmap(NULL, sizeof(code), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (wptr == MAP_FAILED)
        perror_exit("mmap(RW)");
    xptr = mmap(NULL, sizeof(code), PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    if (xptr == MAP_FAILED)
        perror_exit("mmap(RX)");
    printf("RW+RX mmap succeeded at %p and %p in %s\n", wptr, xptr, filename);

    memcpy(wptr, code, sizeof(code));
    if (memcmp(code, xptr, sizeof(code))) {
        fprintf(stderr, "RW and RX mmaps don't share the same data\n");
        return 1;
    }
    result = ((int (*)(void))(uintptr_t)xptr) ();
    if (result != 0) {
        fprintf(stderr, "Unexpected result: %d\n", result);
        return 1;
    } else {
        printf("Code successfully executed\n");
    }

    if (munmap(xptr, sizeof(code)) < 0)
        perror_exit("munmap(RX)");
    if (munmap(wptr, sizeof(code)) < 0)
        perror_exit("munmap(RW)");
    if (close(fd) < 0)
        perror_exit("close");
    return 0;
}
