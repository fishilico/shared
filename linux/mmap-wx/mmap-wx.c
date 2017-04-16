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
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for MAP_ANONYMOUS, ftruncate, mkstemp */
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/**
 * Dump memory mappings after successful code execution
 */
/*#define MMAP_WX_DUMP_MMAPS 1*/

#if defined(__i386__) || defined(__x86_64__)
/**
 * Binary representation of "return 0;" in x86 instruction set:
 *     31 c0      xor    %eax,%eax
 *     c3         ret
 */
static const uint8_t CODE[] = { 0x31, 0xc0, 0xc3 };
#elif defined(__arm__)
/**
 * Binary representation of "return 0;" in ARM instruction set, using the
 * endianness of the compiler:
 *     e3a00000     mov r0, #0
 *     e12fff1e     bx  lr
 */
static const uint32_t CODE[] = { 0xe3a00000, 0xe12fff1e };
#else
#    error Unsupported architecture
#endif

/**
 * Temporary file name
 */
static const char TEMPFILE_SUFFIX[] = "/mmap-wx-tmpXXXXXX";

#if defined(MMAP_WX_DUMP_MMAPS) && MMAP_WX_DUMP_MMAPS
/**
 * Dump current memory mappings
 */
static void dump_proc_maps(void)
{
    char buffer[4096];
    int fd;
    size_t rdlen, wrlen, offset;

    fd = open("/proc/self/maps", O_RDONLY);
    if (fd == -1) {
        perror("[!] open(/proc/self/maps)");
        return;
    }
    while ((rdlen = read(fd, buffer, sizeof(buffer))) > 0) {
        for (offset = 0; offset < rdlen; offset += wrlen) {
            wrlen = fwrite(buffer + offset, 1, rdlen - offset, stdout);
            if (wrlen <= 0) {
                fprintf(stderr, "[!] fwrite failed with error: %d\n",
                        ferror(stdout));
                close(fd);
                return;
            }
        }
    }
    close(fd);
}
#endif

/**
 * Test doing an anonymous RWX mapping, which is denied by grsecurity kernel
 */
static void test_anon_wx_mmap(void)
{
    void *ptr;
    int result;
    ptr = mmap(NULL, sizeof(CODE),
               PROT_READ | PROT_WRITE | PROT_EXEC,
               MAP_PRIVATE | MAP_ANONYMOUS,
               -1, 0);
    if (ptr == MAP_FAILED) {
        if (errno != EACCES && errno != EPERM)
            perror("[-] mmap-RWX");
        printf("[+] Direct RWX mmap failed as expected with a secure kernel\n");
        return;
    }
    printf("[ ] RWX mmap succeeded at %p, let's try to use it!\n", ptr);
    memcpy(ptr, CODE, sizeof(CODE));
    result = ((int (*)(void))(uintptr_t)ptr) ();
    if (munmap(ptr, sizeof(CODE)) < 0)
        perror("[-] munmap-RWX");
    if (result != 0) {
        fprintf(stderr, "[!] unexpected result: %d\n", result);
        return;
    }
    printf("[!] Code successfully executed. Your kernel is NOT secure!\n");
}

/**
 * Test doing an anonymous RW mapping which then becomes executable
 */
static void test_anon_wx_mprotect(void)
{
    int result;
    void *ptr;
    ptr = mmap(NULL, sizeof(CODE),
               PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS,
               -1, 0);
    if (ptr == MAP_FAILED) {
        perror("[-] mmap-RW");
        return;
    }
    printf("[ ] RW mmap succeeded at %p\n", ptr);
    memcpy(ptr, CODE, sizeof(CODE));
    if (mprotect(ptr, sizeof(CODE), PROT_READ | PROT_EXEC) < 0) {
        if (errno != EACCES && errno != EPERM)
            perror("[-] mprotect-RW2RX");
        printf("[+] RX mprotect on a RW mmap failed as expected\n");
        munmap(ptr, sizeof(CODE));
        return;
    }

    result = ((int (*)(void))(uintptr_t)ptr) ();
    if (munmap(ptr, sizeof(CODE)) < 0)
        perror("[-] munmap");
    if (result != 0) {
        fprintf(stderr, "[!] unexpected result: %d\n", result);
        return;
    }
    printf("[~] Code successfully executed after RX mprotect\n");
}

/**
 * Test RW mmap + RX mprotect for a given file descriptor
 */
static void test_mmap_w_mprotect_x_fd(int fd)
{
    void *ptr;
    int result;

    ptr = mmap(NULL, sizeof(CODE), PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (ptr == MAP_FAILED) {
        perror("[!] mmap-RW");
        return;
    }
    printf("... RW mmap succeeded at %p\n", ptr);
    memcpy(ptr, CODE, sizeof(CODE));

    if (mprotect(ptr, sizeof(CODE), PROT_READ | PROT_EXEC) < 0) {
        if (errno != EACCES)
            perror("[!] mprotect-RW2RX");
        else
            printf("... RX mprotect on a RW mmap failed as expected\n");
        munmap(ptr, sizeof(CODE));
        return;
    }
    result = ((int (*)(void))(uintptr_t)ptr) ();
    if (munmap(ptr, sizeof(CODE)) < 0)
        perror("[-] munmap");
    if (result != 0) {
        fprintf(stderr, "[!] unexpected result: %d\n", result);
    }
    printf("[~] Code successfully executed after RX mprotect\n");
}

/**
 * Test RW+RX mmaps for a given file descriptor
 */
static void test_mmap_rw_rx_fd(int fd)
{
    void *wptr, *xptr;
    int result;
    size_t i;

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
                    ((const uint8_t *)CODE)[i], ((uint8_t *)xptr)[i]);
        }
        munmap(xptr, sizeof(CODE));
        munmap(wptr, sizeof(CODE));
        return;
    }

    /* Execute code */
    result = ((int (*)(void))(uintptr_t)xptr) ();
    if (result == 0) {
#if defined(MMAP_WX_DUMP_MMAPS) && MMAP_WX_DUMP_MMAPS
        printf("[+] Code successfully executed. Dump /proc/self/maps\n");
        dump_proc_maps();
#else
        printf("[+] Code successfully executed.\n");
#endif
    } else {
        fprintf(stderr, "[!] Unexpected result: %x\n", result);
    }
    if (munmap(xptr, sizeof(CODE)) < 0)
        perror("[-] munmap-RX");
    if (munmap(wptr, sizeof(CODE)) < 0)
        perror("[-] munmap-RW");
}

/**
 * Test WX mmap for a temporary file in a specified directory
 */
static void test_mmap_wx_dir(const char *dirname)
{
    char filename[4096];
    int fd;
    const size_t dirlen = strlen(dirname);
    if (dirlen + sizeof(TEMPFILE_SUFFIX) + 1 >= sizeof(filename)) {
        fprintf(stderr, "[!] too long directory name: %.512s\n", dirname);
        return;
    }
#if defined(O_TMPFILE) && defined(O_CLOEXEC)
    fd = open(dirname, O_TMPFILE | O_RDWR | O_CLOEXEC | O_EXCL,
              S_IRUSR | S_IWUSR);
    if (fd >= 0) {
        /* Retrieve file name using procfs */
        char procfile[1024];
        ssize_t numbytes;
        snprintf(procfile, sizeof(procfile), "/proc/self/fd/%d", fd);
        numbytes = readlink(procfile, filename, sizeof(filename));
        if (numbytes == -1) {
            perror("[!] readlink");
            snprintf(filename, sizeof(filename), "%s/<deleted file>", dirname);
        } else {
            assert((size_t)numbytes < sizeof(filename));
            filename[numbytes] = 0;
        }
    } else {
        /* EISDIR means kernel doesn't support yet O_TMPFILE */
        if (errno != EISDIR) {
            perror("[!] open");
        }
#endif
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
#if defined(O_TMPFILE) && defined(O_CLOEXEC)
    }
#endif

    /* Expand the file to the used size, otherwise a SIGBUS will be raised */
    if (ftruncate(fd, sizeof(CODE)) < 0) {
        perror("[!] ftruncate");
        return;
    }

    printf("... created file %s\n", filename);
    test_mmap_w_mprotect_x_fd(fd);
    test_mmap_rw_rx_fd(fd);
    close(fd);
}

int main(void)
{
    /* Disable stdout buffering */
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Check that data and function pointers have the same size */
    assert(sizeof(int (*)(void)) == sizeof(void *));

    test_anon_wx_mmap();
    test_anon_wx_mprotect();
    printf("\n");

    printf("[ ] Testing /tmp\n");
    test_mmap_wx_dir("/tmp");
    printf("\n");

    printf("[ ] Testing current directory\n");
    test_mmap_wx_dir(".");
    return 0;
}
