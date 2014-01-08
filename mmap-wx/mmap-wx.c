/**
 * mmap-wx.c
 *
 * Copyright (c) 2014 Nicolas Iooss
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * Binary representation of "return 0;" in x86 assembly language:
 *     31 c0      xor    %eax,%eax
 *     c3         ret
 */
static const char CODE[] = "\x31\xc0\xc3";


/**
 * Temporary file name
 */
static const char TEMPFILE_SUFFIX[] = "/mmap-wx-tmpXXXXXX";


/**
 * Test doing an anonymous RWX mapping, which is denied by grsecurity kernel
 * Return 1 if successful, 0 otherwise
 */
static int test_anon_wx_mmap()
{
    void *ptr;
    int result;
    ptr = mmap(NULL, sizeof(CODE),
               PROT_READ | PROT_WRITE | PROT_EXEC,
               MAP_PRIVATE | MAP_ANONYMOUS,
               -1, 0);
    if (ptr == MAP_FAILED) {
        if (errno != EACCES && errno != EPERM) perror("[-] mmap-RWX");
        printf("[+] Direct RWX mmap failed as expected with a secure kernel\n");
        return 0;
    }
    printf("[ ] RWX mmap succeeded at %p, let's try to use it!\n", ptr);
    memcpy(ptr, CODE, sizeof(CODE));
    result = ( (int (*)())ptr )();
    if (munmap(ptr, sizeof(CODE)) < 0) perror("[-] munmap-RWX");
    if (result != 0) {
        fprintf(stderr, "[!] unexpected result: %d\n", result);
        return 0;
    }
    printf("[!] Code successfully executed. Your kernel is NOT secure!\n");
    return 1;
}

/**
 * Test WX mmap for a given file descriptor
 */
static void test_mmap_wx_fd(int fd)
{
    void *wptr, *xptr;
    int result;
    size_t i;

    /* Expand the file to the used size, otherwise a SIGBUS will be raised */
    if (ftruncate(fd, sizeof(CODE)) < 0) {
        perror("[!] ftruncate");
        return;
    }

    /* RW mmap */
    wptr = mmap(NULL, sizeof(CODE), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (wptr == MAP_FAILED) {
        perror("[!] mmap-RW");
        return;
    }

    /* RX mmap */
    xptr = mmap(NULL, sizeof(CODE), PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    if (xptr == MAP_FAILED) {
        perror("[!] mmap-RX");
        munmap(wptr, sizeof(CODE));
        return;
    }

    printf("... RW+RX mmap succeeded at %p and %p\n", wptr, xptr);

    /* Copy code to the writable mmap and verify the executable map */
    memcpy(wptr, CODE, sizeof(CODE));
    if (memcmp(CODE, xptr, sizeof(CODE))) {
        fprintf(stderr, "[!] RW and RX mmaps are different:\n");
        for (i = 0; i < sizeof(CODE); i++) {
            fprintf(stderr, "... %02x %02x\n",
                    CODE[i], ((char*)xptr)[i]);
        }
        munmap(xptr, sizeof(CODE));
        munmap(wptr, sizeof(CODE));
        return;
    }

    /* Execute code */
    result = ( (int (*)())xptr )();
    if (munmap(xptr, sizeof(CODE)) < 0) perror("[-] munmap-RX");
    if (munmap(wptr, sizeof(CODE)) < 0) perror("[-] munmap-RW");
    if (result != 0) {
        fprintf(stderr, "[!] Unexpected result: %x\n", result);
        return;
    }
    printf("[+] Code successfully executed\n");
}

/**
 * Test WX mmap for a temporary file in a specified directory
 */
static void test_mmap_wx_dir(const char *dirname)
{
    char filename[4096];
    int fd;
    const int dirlen = strlen(dirname);
    if (dirlen + sizeof(TEMPFILE_SUFFIX) + 1 >= sizeof(filename)) {
        fprintf(stderr, "[!] too long directory name: %.512s\n", dirname);
        return;
    }

    memcpy(filename, dirname, dirlen);
    memcpy(filename + dirlen, TEMPFILE_SUFFIX, sizeof(TEMPFILE_SUFFIX));

    /* Create file */
    fd = mkstemp(filename);
    if (fd == -1) {
        perror("mkstemp");
        fprintf(stderr, "[!] failed to create file in %s", dirname);
        return;
    }

    /* Unlink it so that only the program can see it */
    if (unlink(filename) < 0) {
        perror("unlink");
        fprintf(stderr, "[!] failed to unlink %s", filename);
        return;
    }
    printf("... created file %s\n", filename);
    test_mmap_wx_fd(fd);
    close(fd);
}

int main()
{
    /* Disable stdout buffering */
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Check that data and function pointers have the same size */
    assert(sizeof(int (*)()) == sizeof(void*));

    if (test_anon_wx_mmap()) return 1;
    printf("\n");

    printf("[ ] Testing /tmp\n");
    test_mmap_wx_dir("/tmp");
    printf("\n");

    printf("[ ] Testing current directory\n");
    test_mmap_wx_dir(".");
    return 0;
}
