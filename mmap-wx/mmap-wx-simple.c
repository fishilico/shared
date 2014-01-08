/**
 * mmap-wx-simple.c
 *
 * Simpler version of mmap-wx.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

void perror_exit(const char *s)
{
    perror(s);
    exit(1);
}

int main()
{
    const char template[] = "./mmap-wx-XXXXXX";
    /* "xor %eax,%eax ; ret" in x86  */
    const char code[] = "\x31\xc0\xc3";
    char filename[4096];
    int fd, result;
    void *wptr, *xptr;

    memcpy(filename, template, sizeof(template));
    fd = mkstemp(filename);
    if (fd == -1) perror_exit("mkstemp");
    if (unlink(filename) < 0) perror_exit("unlink");
    if (ftruncate(fd, sizeof(code)) < 0) perror_exit("ftruncate");
    wptr = mmap(NULL, sizeof(code), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (wptr == MAP_FAILED) perror_exit("mmap(RW)");
    xptr = mmap(NULL, sizeof(code), PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    if (xptr == MAP_FAILED) perror_exit("mmap(RX)");
    printf("RW+RX mmap succeeded at %p and %p in %s\n", wptr, xptr, filename);

    memcpy(wptr, code, sizeof(code));
    if (memcmp(code, xptr, sizeof(code))) {
        fprintf(stderr, "RW and RX mmaps don't share the same data\n");
        return 1;
    }
    result = ( (int (*)())xptr )();
    if (result != 0) {
        fprintf(stderr, "Unexpected result: %d\n", result);
        return 1;
    } else {
        printf("Code successfully executed\n");
    }

    if (munmap(xptr, sizeof(code)) < 0) perror_exit("munmap(RX)");
    if (munmap(wptr, sizeof(code)) < 0) perror_exit("munmap(RW)");
    if (close(fd) < 0) perror_exit("close");
    return 0;
}
